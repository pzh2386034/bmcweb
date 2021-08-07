/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
#pragma once
#include "node.hpp"

#include <dbus_utility.hpp>
#include <error_messages.hpp>
#include <openbmc_dbus_rest.hpp>
#include <persistent_data.hpp>
#include <utils/json_utils.hpp>

#include <variant>
#include <boost/algorithm/string/split.hpp>
#include <boost/process/child.hpp>
#include <boost/process/io.hpp>
#include <boost/exception/all.hpp>
#include <exception>
namespace redfish
{

constexpr const char* ldapConfigObjectName =
    "/xyz/openbmc_project/user/ldap/openldap";
constexpr const char* adConfigObject =
    "/xyz/openbmc_project/user/ldap/active_directory";

constexpr const char* ldapRootObject = "/xyz/openbmc_project/user/ldap";
constexpr const char* ldapDbusService = "xyz.openbmc_project.Ldap.Config";
constexpr const char* ldapConfigInterface =
    "xyz.openbmc_project.User.Ldap.Config";
constexpr const char* ldapCreateInterface =
    "xyz.openbmc_project.User.Ldap.Create";
constexpr const char* ldapEnableInterface = "xyz.openbmc_project.Object.Enable";
constexpr const char* ldapPrivMapperInterface =
    "xyz.openbmc_project.User.PrivilegeMapper";
constexpr const char* dbusObjManagerIntf = "org.freedesktop.DBus.ObjectManager";
constexpr const char* propertyInterface = "org.freedesktop.DBus.Properties";
constexpr const char* mapperBusName = "xyz.openbmc_project.ObjectMapper";
constexpr const char* mapperObjectPath = "/xyz/openbmc_project/object_mapper";
constexpr const char* mapperIntf = "xyz.openbmc_project.ObjectMapper";

struct LDAPRoleMapData
{
    std::string groupName;
    std::string privilege;
};

struct LDAPConfigData
{
    std::string uri{};
    std::string bindDN{};
    std::string baseDN{};
    std::string searchScope{};
    std::string serverType{};
    bool serviceEnabled = false;
    std::string userNameAttribute{};
    std::string groupAttribute{};
    std::vector<std::pair<std::string, LDAPRoleMapData>> groupRoleList;
};

using DbusVariantType = std::variant<bool, int32_t, std::string>;

using DbusInterfaceType = boost::container::flat_map<
    std::string, boost::container::flat_map<std::string, DbusVariantType>>;

using ManagedObjectType =
    std::vector<std::pair<sdbusplus::message::object_path, DbusInterfaceType>>;

using GetObjectType =
    std::vector<std::pair<std::string, std::vector<std::string>>>;

inline std::string getRoleIdFromPrivilege(std::string_view role)
{
    if (role == "priv-admin")
    {
        return "Administrator";
    }
    else if (role == "priv-user")
    {
        return "ReadOnly";
    }
    else if (role == "priv-operator")
    {
        return "Operator";
    }
    else if ((role == "") || (role == "priv-noaccess"))
    {
        return "NoAccess";
    }
    return "";
}
inline std::string getPrivilegeFromRoleId(std::string_view role)
{
    if (role == "Administrator")
    {
        return "priv-admin";
    }
    else if (role == "ReadOnly")
    {
        return "priv-user";
    }
    else if (role == "Operator")
    {
        return "priv-operator";
    }
    else if ((role == "NoAccess") || (role == ""))
    {
        return "priv-noaccess";
    }
    return "";
}


template <typename... ArgTypes>
static std::vector<std::string> executeCmd(const char* path,
                                           ArgTypes&&... tArgs)
{
    std::vector<std::string> stdOutput;
    boost::process::ipstream stdOutStream;
    boost::process::child execProg(path, const_cast<char*>(tArgs)...,
                                   boost::process::std_out > stdOutStream);
    std::string stdOutLine;

    while (stdOutStream && std::getline(stdOutStream, stdOutLine) &&
           !stdOutLine.empty())
    {
        stdOutput.emplace_back(stdOutLine);
    }

    execProg.wait();

    int retCode = execProg.exit_code();
    if (retCode)
    {
        BMCWEB_LOG_ERROR<<"Command execution failed, "<<"PATH="<<path<<", RETURN_CODE:"<<retCode;
    }

    return stdOutput;
}

static std::string getCSVFromVector(std::vector<std::string> vec)
{
    switch (vec.size())
    {
        case 0:
        {
            return "";
        }
        break;

        case 1:
        {
            return std::string{vec[0]};
        }
        break;

        default:
        {
            return std::accumulate(
                std::next(vec.begin()), vec.end(), vec[0],
                [](std::string a, std::string b) { return a + ',' + b; });
        }
    }
}
class AccountsCollection : public Node
{
  public:
    AccountsCollection(App& app) :
        Node(app, "/redfish/v1/AccountService/Accounts/")
    {
        entityPrivileges = {
            // According to the PrivilegeRegistry, GET should actually be
            // "Login". A "Login" only privilege would return an empty "Members"
            // list. Not going to worry about this since none of the defined
            // roles are just "Login". E.g. Readonly is {"Login",
            // "ConfigureSelf"}. In the rare event anyone defines a role that
            // has Login but not ConfigureSelf, implement this.
            {boost::beast::http::verb::get,
             {{"ConfigureUsers"}, {"ConfigureSelf"}}},
            {boost::beast::http::verb::head, {{"Login"}}},
            {boost::beast::http::verb::patch, {{"ConfigureUsers"}}},
            {boost::beast::http::verb::put, {{"ConfigureUsers"}}},
            {boost::beast::http::verb::delete_, {{"ConfigureUsers"}}},
            {boost::beast::http::verb::post, {{"ConfigureUsers"}}}};
    }

  private:
    void doGet(crow::Response& res, const crow::Request& req,
               const std::vector<std::string>&) override
    {
        auto asyncResp = std::make_shared<AsyncResp>(res);
        res.jsonValue = {{"@odata.id", "/redfish/v1/AccountService/Accounts"},
                         {"@odata.type", "#ManagerAccountCollection."
                                         "ManagerAccountCollection"},
                         {"Name", "Accounts Collection"},
                         {"Description", "BMC User Accounts"}};

        crow::connections::systemBus->async_method_call(
            [asyncResp, &req, this](const boost::system::error_code ec,
                                    const ManagedObjectType& users) {
                if (ec)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }

                nlohmann::json& memberArray =
                    asyncResp->res.jsonValue["Members"];
                memberArray = nlohmann::json::array();

                for (auto& user : users)
                {
                    const std::string& path =
                        static_cast<const std::string&>(user.first);
                    std::size_t lastIndex = path.rfind("/");
                    if (lastIndex == std::string::npos)
                    {
                        lastIndex = 0;
                    }
                    else
                    {
                        lastIndex += 1;
                    }

                    // As clarified by Redfish here:
                    // https://redfishforum.com/thread/281/manageraccountcollection-change-allows-account-enumeration
                    // Users without ConfigureUsers, only see their own account.
                    // Users with ConfigureUsers, see all accounts.
                    if (req.session->username == path.substr(lastIndex) ||
                        isAllowedWithoutConfigureSelf(req))
                    {
                        memberArray.push_back(
                            {{"@odata.id",
                              "/redfish/v1/AccountService/Accounts/" +
                                  path.substr(lastIndex)}});
                    }
                }
                asyncResp->res.jsonValue["Members@odata.count"] =
                    memberArray.size();
            },
            "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
    }
    void doPost(crow::Response& res, const crow::Request& req,
                const std::vector<std::string>&) override
    {
        std::string username;
        std::string password;
        std::optional<std::string> roleId("User");
        std::optional<bool> enabled = true;
        std::optional<std::string> productorGroups("");
        if (!json_util::readJson(req, res, "UserName", username, "Password",
                                 password, "RoleId", roleId, "Enabled",
                                 enabled, "Groups", productorGroups))
        {
            return;
        }

        std::string priv = getPrivilegeFromRoleId(*roleId);
        if (priv.empty())
        {
            messages::propertyValueNotInList(res, *roleId, "RoleId");
            return;
        }
        // TODO: Following override will be reverted once support in
        // phosphor-user-manager is added. In order to avoid dependency issues,
        // this is added in bmcweb, which will removed, once
        // phosphor-user-manager supports priv-noaccess.
        if (priv == "priv-noaccess")
        {
            roleId = "";
        }
        else
        {
            roleId = priv;
        }

        
        try
        {
            executeCmd("/usr/sbin/useradd", username.c_str(), "-G", productorGroups->c_str(),
                    "-N", "-s", "/bin/false", "-e",
                    (enabled ? "" : "1970-01-02"));
        }
        catch (boost::exception &e)
        {
            BMCWEB_LOG_ERROR<<"useradd "<<username.c_str()<<" failed:";
            messages::internalError(res);
        }

        if (pamUpdatePassword(username, password) !=
            PAM_SUCCESS)
        {
            // At this point we have a user that's been created,
            // but the password set failed.Something is wrong,
            // so delete the user that we've already created
            try
            {
                executeCmd("/usr/sbin/userdel", username.c_str());
            }
            catch (boost::exception &e)
            {
                BMCWEB_LOG_ERROR<<"userdel "<<username.c_str()<<" failed:";
            }

            BMCWEB_LOG_ERROR << "pamUpdatePassword Failed";
            messages::internalError(res);
            return;
        }

    }
};

class ManagerAccount : public Node
{
  public:
    ManagerAccount(App& app) :
        Node(app, "/redfish/v1/AccountService/Accounts/<str>/", std::string())
    {
        entityPrivileges = {
            {boost::beast::http::verb::get,
             {{"ConfigureUsers"}, {"ConfigureManager"}, {"ConfigureSelf"}}},
            {boost::beast::http::verb::head, {{"Login"}}},
            {boost::beast::http::verb::patch,
             {{"ConfigureUsers"}, {"ConfigureSelf"}}},
            {boost::beast::http::verb::put, {{"ConfigureUsers"}}},
            {boost::beast::http::verb::delete_, {{"ConfigureUsers"}}},
            {boost::beast::http::verb::post, {{"ConfigureUsers"}}}};
    }

  private:
    void doGet(crow::Response& res, const crow::Request& req,
               const std::vector<std::string>& params) override
    {
        auto asyncResp = std::make_shared<AsyncResp>(res);

        if (params.size() != 1)
        {
            messages::internalError(asyncResp->res);
            return;
        }

        // Perform a proper ConfigureSelf authority check.  If the
        // user is operating on an account not their own, then their
        // ConfigureSelf privilege does not apply.  In this case,
        // perform the authority check again without the user's
        // ConfigureSelf privilege.
        if (req.session->username != params[0])
        {
            if (!isAllowedWithoutConfigureSelf(req))
            {
                BMCWEB_LOG_DEBUG << "GET Account denied access";
                messages::insufficientPrivilege(asyncResp->res);
                return;
            }
        }

        crow::connections::systemBus->async_method_call(
            [asyncResp, accountName{std::string(params[0])}](
                const boost::system::error_code ec,
                const ManagedObjectType& users) {
                if (ec)
                {
                    messages::internalError(asyncResp->res);
                    return;
                }
                auto userIt = users.begin();

                for (; userIt != users.end(); userIt++)
                {
                    if (boost::ends_with(userIt->first.str, "/" + accountName))
                    {
                        break;
                    }
                }
                if (userIt == users.end())
                {
                    messages::resourceNotFound(asyncResp->res, "ManagerAccount",
                                               accountName);
                    return;
                }

                asyncResp->res.jsonValue = {
                    {"@odata.type", "#ManagerAccount.v1_4_0.ManagerAccount"},
                    {"Name", "User Account"},
                    {"Description", "User Account"},
                    {"Password", nullptr},
                    {"AccountTypes", {"Redfish"}}};

                for (const auto& interface : userIt->second)
                {
                    if (interface.first ==
                        "xyz.openbmc_project.User.Attributes")
                    {
                        for (const auto& property : interface.second)
                        {
                            if (property.first == "UserEnabled")
                            {
                                const bool* userEnabled =
                                    std::get_if<bool>(&property.second);
                                if (userEnabled == nullptr)
                                {
                                    BMCWEB_LOG_ERROR
                                        << "UserEnabled wasn't a bool";
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                asyncResp->res.jsonValue["Enabled"] =
                                    *userEnabled;
                            }
                            else if (property.first ==
                                     "UserLockedForFailedAttempt")
                            {
                                const bool* userLocked =
                                    std::get_if<bool>(&property.second);
                                if (userLocked == nullptr)
                                {
                                    BMCWEB_LOG_ERROR << "UserLockedForF"
                                                        "ailedAttempt "
                                                        "wasn't a bool";
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                asyncResp->res.jsonValue["Locked"] =
                                    *userLocked;
                                asyncResp->res.jsonValue
                                    ["Locked@Redfish.AllowableValues"] = {
                                    "false"}; // can only unlock accounts
                            }
                            else if (property.first == "UserPrivilege")
                            {
                                const std::string* userPrivPtr =
                                    std::get_if<std::string>(&property.second);
                                if (userPrivPtr == nullptr)
                                {
                                    BMCWEB_LOG_ERROR
                                        << "UserPrivilege wasn't a "
                                           "string";
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                std::string role =
                                    getRoleIdFromPrivilege(*userPrivPtr);
                                if (role.empty())
                                {
                                    BMCWEB_LOG_ERROR << "Invalid user role";
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                asyncResp->res.jsonValue["RoleId"] = role;

                                asyncResp->res.jsonValue["Links"]["Role"] = {
                                    {"@odata.id", "/redfish/v1/AccountService/"
                                                  "Roles/" +
                                                      role}};
                            }
                            else if (property.first == "UserPasswordExpired")
                            {
                                const bool* userPasswordExpired =
                                    std::get_if<bool>(&property.second);
                                if (userPasswordExpired == nullptr)
                                {
                                    BMCWEB_LOG_ERROR << "UserPassword"
                                                        "Expired "
                                                        "wasn't a bool";
                                    messages::internalError(asyncResp->res);
                                    return;
                                }
                                asyncResp->res
                                    .jsonValue["PasswordChangeRequired"] =
                                    *userPasswordExpired;
                            }
                        }
                    }
                }

                asyncResp->res.jsonValue["@odata.id"] =
                    "/redfish/v1/AccountService/Accounts/" + accountName;
                asyncResp->res.jsonValue["Id"] = accountName;
                asyncResp->res.jsonValue["UserName"] = accountName;
            },
            "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
    }

    void doPatch(crow::Response& res, const crow::Request& req,
                 const std::vector<std::string>& params) override
    {
        auto asyncResp = std::make_shared<AsyncResp>(res);
        if (params.size() != 1)
        {
            messages::internalError(asyncResp->res);
            return;
        }

        std::optional<std::string> newUserName;
        std::optional<std::string> password;
        std::optional<bool> enabled;
        std::optional<std::string> roleId;
        std::optional<bool> locked;
        if (!json_util::readJson(req, res, "UserName", newUserName, "Password",
                                 password, "RoleId", roleId, "Enabled", enabled,
                                 "Locked", locked))
        {
            return;
        }

        const std::string& username = params[0];

        // Perform a proper ConfigureSelf authority check.  If the
        // session is being used to PATCH a property other than
        // Password, then the ConfigureSelf privilege does not apply.
        // If the user is operating on an account not their own, then
        // their ConfigureSelf privilege does not apply.  In either
        // case, perform the authority check again without the user's
        // ConfigureSelf privilege.
        if ((username != req.session->username) ||
            (newUserName || enabled || roleId || locked))
        {
            if (!isAllowedWithoutConfigureSelf(req))
            {
                BMCWEB_LOG_WARNING << "PATCH Password denied access";
                asyncResp->res.clear();
                messages::insufficientPrivilege(asyncResp->res);
                return;
            }
        }

        // if user name is not provided in the patch method or if it
        // matches the user name in the URI, then we are treating it as updating
        // user properties other then username. If username provided doesn't
        // match the URI, then we are treating this as user rename request.
        if (!newUserName || (newUserName.value() == username))
        {
            updateUserProperties(asyncResp, username, password, enabled, roleId,
                                 locked);
            return;
        }
        else
        {
            crow::connections::systemBus->async_method_call(
                [this, asyncResp, username, password(std::move(password)),
                 roleId(std::move(roleId)), enabled(std::move(enabled)),
                 newUser{std::string(*newUserName)},
                 locked(std::move(locked))](const boost::system::error_code ec,
                                            sdbusplus::message::message& ) {
                    if (ec)
                    {
                        //userErrorMessageHandler(m.get_error(), asyncResp,newUser, username);
                        return;
                    }

                    updateUserProperties(asyncResp, newUser, password, enabled,
                                         roleId, locked);
                },
                "xyz.openbmc_project.User.Manager", "/xyz/openbmc_project/user",
                "xyz.openbmc_project.User.Manager", "RenameUser", username,
                *newUserName);
        }
    }

    void updateUserProperties(std::shared_ptr<AsyncResp> asyncResp,
                              const std::string& username,
                              std::optional<std::string> password,
                              std::optional<bool> enabled,
                              std::optional<std::string> roleId,
                              std::optional<bool> locked)
    {
        std::string dbusObjectPath = "/xyz/openbmc_project/user/" + username;
        dbus::utility::escapePathForDbus(dbusObjectPath);

        dbus::utility::checkDbusPathExists(
            dbusObjectPath,
            [dbusObjectPath(std::move(dbusObjectPath)), username,
             password(std::move(password)), roleId(std::move(roleId)),
             enabled(std::move(enabled)), locked(std::move(locked)),
             asyncResp{std::move(asyncResp)}](int rc) {
                if (!rc)
                {
                    messages::resourceNotFound(
                        asyncResp->res, "#ManagerAccount.v1_4_0.ManagerAccount",
                        username);
                    return;
                }

                if (password)
                {
                    int retval = pamUpdatePassword(username, *password);

                    if (retval == PAM_USER_UNKNOWN)
                    {
                        messages::resourceNotFound(
                            asyncResp->res,
                            "#ManagerAccount.v1_4_0.ManagerAccount", username);
                    }
                    else if (retval == PAM_AUTHTOK_ERR)
                    {
                        // If password is invalid
                        messages::propertyValueFormatError(
                            asyncResp->res, *password, "Password");
                        BMCWEB_LOG_ERROR << "pamUpdatePassword Failed";
                    }
                    else if (retval != PAM_SUCCESS)
                    {
                        messages::internalError(asyncResp->res);
                        return;
                    }
                }

                if (enabled)
                {
                    crow::connections::systemBus->async_method_call(
                        [asyncResp](const boost::system::error_code ec) {
                            if (ec)
                            {
                                BMCWEB_LOG_ERROR << "D-Bus responses error: "
                                                 << ec;
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            messages::success(asyncResp->res);
                            return;
                        },
                        "xyz.openbmc_project.User.Manager",
                        dbusObjectPath.c_str(),
                        "org.freedesktop.DBus.Properties", "Set",
                        "xyz.openbmc_project.User.Attributes", "UserEnabled",
                        std::variant<bool>{*enabled});
                }

                if (roleId)
                {
                    std::string priv = getPrivilegeFromRoleId(*roleId);
                    if (priv.empty())
                    {
                        messages::propertyValueNotInList(asyncResp->res,
                                                         *roleId, "RoleId");
                        return;
                    }
                    if (priv == "priv-noaccess")
                    {
                        priv = "";
                    }

                    crow::connections::systemBus->async_method_call(
                        [asyncResp](const boost::system::error_code ec) {
                            if (ec)
                            {
                                BMCWEB_LOG_ERROR << "D-Bus responses error: "
                                                 << ec;
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            messages::success(asyncResp->res);
                        },
                        "xyz.openbmc_project.User.Manager",
                        dbusObjectPath.c_str(),
                        "org.freedesktop.DBus.Properties", "Set",
                        "xyz.openbmc_project.User.Attributes", "UserPrivilege",
                        std::variant<std::string>{priv});
                }

                if (locked)
                {
                    // admin can unlock the account which is locked by
                    // successive authentication failures but admin should
                    // not be allowed to lock an account.
                    if (*locked)
                    {
                        messages::propertyValueNotInList(asyncResp->res, "true",
                                                         "Locked");
                        return;
                    }

                    crow::connections::systemBus->async_method_call(
                        [asyncResp](const boost::system::error_code ec) {
                            if (ec)
                            {
                                BMCWEB_LOG_ERROR << "D-Bus responses error: "
                                                 << ec;
                                messages::internalError(asyncResp->res);
                                return;
                            }
                            messages::success(asyncResp->res);
                            return;
                        },
                        "xyz.openbmc_project.User.Manager",
                        dbusObjectPath.c_str(),
                        "org.freedesktop.DBus.Properties", "Set",
                        "xyz.openbmc_project.User.Attributes",
                        "UserLockedForFailedAttempt",
                        std::variant<bool>{*locked});
                }
            });
    }

    void doDelete(crow::Response& res, const crow::Request&,
                  const std::vector<std::string>& params) override
    {
        auto asyncResp = std::make_shared<AsyncResp>(res);

        if (params.size() != 1)
        {
            messages::internalError(asyncResp->res);
            return;
        }

        const std::string userPath = "/xyz/openbmc_project/user/" + params[0];

        crow::connections::systemBus->async_method_call(
            [asyncResp, username{std::move(params[0])}](
                const boost::system::error_code ec) {
                if (ec)
                {
                    messages::resourceNotFound(
                        asyncResp->res, "#ManagerAccount.v1_4_0.ManagerAccount",
                        username);
                    return;
                }

                messages::accountRemoved(asyncResp->res);
            },
            "xyz.openbmc_project.User.Manager", userPath,
            "xyz.openbmc_project.Object.Delete", "Delete");
    }
};

} // namespace redfish
