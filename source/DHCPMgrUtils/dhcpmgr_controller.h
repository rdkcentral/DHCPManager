/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef _DHCP_CONTROLLER_H_
#define _DHCP_CONTROLLER_H_

/**
 * @brief Starts the main controller thread.
 *
 * This function initializes and starts the main controller thread for the DHCP Manager.
 *
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int DhcpMgr_StartMainController();

#endif //_DHCP_CONTROLLER_H_