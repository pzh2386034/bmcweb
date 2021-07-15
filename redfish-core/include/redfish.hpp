/*
// Copyright (c) 2018-2019 Intel Corporation
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

#include "../lib/account_service.hpp"
#include "../lib/bios.hpp"
#include "../lib/certificate_service.hpp"
#include "../lib/chassis.hpp"
#include "../lib/cpudimm.hpp"
#include "../lib/ethernet.hpp"
#include "../lib/event_service.hpp"
#include "../lib/log_services.hpp"
#include "../lib/managers.hpp"
#include "../lib/message_registries.hpp"
#include "../lib/network_protocol.hpp"
#include "../lib/pcie.hpp"
#include "../lib/power.hpp"
#include "../lib/redfish_sessions.hpp"
#include "../lib/roles.hpp"
#include "../lib/sensors.hpp"
#include "../lib/service_root.hpp"
#include "../lib/storage.hpp"
#include "../lib/systems.hpp"
#include "../lib/task.hpp"
#include "../lib/thermal.hpp"
#include "../lib/update_service.hpp"
#ifdef BMCWEB_ENABLE_VM_NBDPROXY
#include "../lib/virtual_media.hpp"
#endif // BMCWEB_ENABLE_VM_NBDPROXY
#include "../lib/hypervisor_ethernet.hpp"

namespace redfish
{
/*
 * @brief Top level class installing and providing Redfish services
 */
class RedfishService
{
  public:
    /*
     * @brief Redfish service constructor
     *
     * Loads Redfish configuration and installs schema resources
     *
     * @param[in] app   Crow app on which Redfish will initialize
     */
    RedfishService(App& app)
    {
        nodes.emplace_back(std::make_unique<AccountService>(app));
        nodes.emplace_back(std::make_unique<AccountsCollection>(app));
        nodes.emplace_back(std::make_unique<ManagerAccount>(app));
        nodes.emplace_back(std::make_unique<SessionCollection>(app));
        nodes.emplace_back(std::make_unique<Roles>(app));
        nodes.emplace_back(std::make_unique<RoleCollection>(app));
        nodes.emplace_back(std::make_unique<ServiceRoot>(app));
        nodes.emplace_back(std::make_unique<Systems>(app));


        for (const auto& node : nodes)
        {
            node->initPrivileges();
        }
    }

  private:
    std::vector<std::unique_ptr<Node>> nodes;
};

} // namespace redfish
