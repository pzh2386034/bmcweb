#pragma once
#include <sdbusplus/asio/connection.hpp>
#include "zdbpp.h"

namespace crow
{
namespace connections
{
static std::shared_ptr<sdbusplus::asio::connection> systemBus;

} // namespace connections
namespace dbconnections
{
static std::shared_ptr<zdb::ConnectionPool> dbpoll;
}
} // namespace crow
