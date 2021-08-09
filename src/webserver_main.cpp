#include <app.h>
#include <systemd/sd-daemon.h>

#include <boost/asio/io_context.hpp>
#include <dbus_monitor.hpp>
#include <dbus_singleton.hpp>
#include <ibm/management_console_rest.hpp>
#include <image_upload.hpp>
#include <kvm_websocket.hpp>
#include <login_routes.hpp>
#include <obmc_console.hpp>
#include <openbmc_dbus_rest.hpp>
#include <redfish.hpp>
#include <redfish_v1.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server.hpp>
#include <security_headers.hpp>
#include <ssl_key_handler.hpp>
#include <vm_websocket.hpp>
#include <webassets.hpp>

#include <memory>
#include <string>
#include "curl/curl.h"

#ifdef BMCWEB_ENABLE_VM_NBDPROXY
#include <nbd_proxy.hpp>
#endif

constexpr int defaultPort = 443;
std::string sqldb("mysql://localhost:3306/bankcard?user=root&password=0penBmc");

inline void setupSocket(crow::App& app)
{
    int listenFd = sd_listen_fds(0);
    if (1 == listenFd)
    {
        BMCWEB_LOG_INFO << "attempting systemd socket activation";
        if (sd_is_socket_inet(SD_LISTEN_FDS_START, AF_UNSPEC, SOCK_STREAM, 1,
                              0))
        {
            BMCWEB_LOG_INFO << "Starting webserver on socket handle "
                            << SD_LISTEN_FDS_START;
            app.socket(SD_LISTEN_FDS_START);
        }
        else
        {
            BMCWEB_LOG_INFO
                << "bad incoming socket, starting webserver on port "
                << defaultPort;
            app.port(defaultPort);
        }
    }
    else
    {
        BMCWEB_LOG_INFO << "Starting webserver on port " << defaultPort;
        app.port(defaultPort);
    }
}

int main(int /*argc*/, char** /*argv*/)
{
    crow::Logger::setLogLevel(crow::LogLevel::Debug);

    auto io = std::make_shared<boost::asio::io_context>();
    App app(io);

    // Static assets need to be initialized before Authorization, because auth
    // needs to build the whitelist from the static routes


    crow::login_routes::requestRoutes(app);

    setupSocket(app);
    curl_global_init(CURL_GLOBAL_ALL);
    crow::connections::systemBus =
        std::make_shared<sdbusplus::asio::connection>(*io);
    crow::dbconnections::dbpoll = std::make_shared<zdb::ConnectionPool>(sqldb);
    crow::dbconnections::dbpoll->start();


    redfish::RedfishService redfish(app);


    app.run();
    io->run();

    crow::connections::systemBus.reset();
}
