/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2020 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
************************************************************************************/

#ifndef __INTERFACE_LAYER_CONF_H__
#define __INTERFACE_LAYER_CONF_H__

/*
 * Tailor fit the below macro configurations as per the
 * component need.
 */

/* No. of threads that will share the work load.
 * A queue/ctx can have dedicated one or more or no threads
 * depending on the requirement of the application.
 */
#define IFL_MAX_TASK_THRD          4

/*
 * MAx number of records for task resources
 */
#define IFL_MAX_TASK_RESOURCE      24

/* No. of queues that will be required by the application.
 * One queue per thread would be supported for now.
 * Hence, load sharing would be supported later.
 */
#define IFL_MAX_QUEUE              4

/*
 * Max number of items for queue.
 */
#define IFL_MAX_QLEN               12

/* No. of context that will be required by the application.
 * One context per queue is ideal. One queue cannot have more
 * than one context. Hence, load sharing would be supported
 * later.
 */
#define IFL_MAX_CONTEXT            4

/* Enable/Disable mapping of one thrd to one queue to one
 * context.
 */
#define IFL_MAP_THRD_QUEUE_CTX     1

/*
 * Max number of items for event hanlers map.
 */
#define IFL_MAX_EVENT_HANDLER_MAP  24

#endif
