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

#define _GNU_SOURCE
#include <pthread.h>
#include <errno.h>
#include "ifl_conf.h"
#include "ifl_priv.h"

#define IFL_THREAD_DEFAULT_PRIORITY 5
#define IFL_THREAD_LOW_PRIORITY     0

typedef void*(*tfptr_t)(void*);
typedef void ifl_lock_t;

typedef enum _thread_prop {
    IFL_THRD_PROP_NONE              = 0x00,
    IFL_THRD_PROP_JOIN              = 0x01,
    IFL_THRD_PROP_DETACH            = 0x02,
    IFL_THRD_PROP_CANCEL            = 0x04,
    IFL_THRD_PROP_NO_CANCEL         = 0x08,
    IFL_THRD_PROP_CANCEL_ASYNC      = 0x10,
    IFL_THRD_PROP_CANCEL_DEFER      = 0x20,
    /*
     * fill here
     */
    IFL_THRD_PROP_MAX               = 0xFF
} thread_prop;

typedef enum _lock_prop {
    IFL_LOCK_PROP_NONE              = 0x00,
    IFL_LOCK_PROP_ROBUST            = 0x01,
    IFL_LOCK_PROP_INHERIT_PRIORITY  = 0x02,
    IFL_LOCK_PROP_PROCESS_PRIVATE   = 0x04,
    IFL_LOCK_PROP_PROCESS_SHARED    = 0x08,
    /*
     * fill here
     */
    IFL_LOCK_PROP_MAX               = 0xFF
} lock_prop;

typedef enum _lock_type {
    IFL_LOCK_TYPE_MUTEX             = 0x00,
    IFL_LOCK_TYPE_MUTEX_WAIT        = 0x01,
    IFL_LOCK_TYPE_MUTEX_NO_WAIT     = 0x02,
    IFL_LOCK_TYPE_SPIN              = 0x04,
    IFL_LOCK_TYPE_SPIN_WAIT         = 0x08,
    IFL_LOCK_TYPE_SPIN_NO_WAIT      = 0x10,
    IFL_LOCK_TYPE_SEM               = 0x20,
    /*
     * fill here
     */
    IFL_LOCK_TYPE_MAX               = 0xFF
} lock_type;

// Seperate mutex specific properties

/*
 * Static globals
 */
static pthread_mutex_t     mLock[IFL_MAX_CONTEXT];
static pthread_spinlock_t  sLock[IFL_MAX_CONTEXT];

/*
 * Static API prototypes
 */
static int _what_is_the_problem (uint8 tID, int rc, char* errPrefix);
static ifl_ret _ifl_thread_set_priority (pthread_t tID, int policy, int priority);



/*
 * Static API definitions
 */
static int _what_is_the_problem (uint8 tID, int rc, char* errPrefix)
{
    switch (rc)
    {
        case EINVAL:  IFL_LOG_ERROR("[%d] %s - Invalid! ", tID, errPrefix);
                      break;
        case ENOTSUP: IFL_LOG_ERROR("[%d] %s - Not Supported!", tID, errPrefix);
                      break;
        case ESRCH:   IFL_LOG_ERROR("[%d] %s - Thread Not Found!", tID, errPrefix);
                      break;
        case EDEADLK: IFL_LOG_ERROR("[%d] %s - !!!DEADLOCK!!!", tID, errPrefix);
                      break;
        case EPERM:   IFL_LOG_ERROR("[%d] %s - Insufficient Privilege!", tID, errPrefix);
                      break;
        case EAGAIN:  IFL_LOG_ERROR("[%d] %s - Insufficient Resources!", tID, errPrefix);
                      break;
        case ENOMEM:  IFL_LOG_ERROR("[%d] %s - Insufficient Memory!", tID, errPrefix);
                      break;
        default:      IFL_LOG_ERROR("[%d] %s - Unhandled Failure(%d)!", tID, errPrefix, rc);
    }
    return rc;
}


static ifl_ret _ifl_thread_set_priority (pthread_t tID, int policy ,int priority)
{
    struct sched_param param;

    param.sched_priority = priority;
    /* Should be aware of using pthread_yield(), for better cpu gain */
    /* Real time scheduling choosed by default for now */
    return pthread_setschedparam(tID, policy, &param);
}


/*
 * External API definitions
 */
ifl_ret ifl_lock_init (ifl_lock_t** lock)
{
    ifl_ret ret = IFL_ERROR;
    pthread_mutexattr_t mAttr;
    pthread_mutex_t*  mtLock = *lock = NULL;
    int rc = -1;

    if ((rc = pthread_mutexattr_init(&mAttr)))
    {
        _what_is_the_problem(111, rc, "Mutex attr init failed");
    }
    else
    if ((rc = pthread_mutexattr_setrobust(&mAttr,   PTHREAD_MUTEX_ROBUST)
            | pthread_mutexattr_setprotocol(&mAttr, PTHREAD_PRIO_INHERIT)
            | pthread_mutexattr_setpshared(&mAttr,  PTHREAD_PROCESS_PRIVATE)))
    {
        _what_is_the_problem(111, rc, "Mutex attr set failed");
    }
    else
    if (!(mtLock = (pthread_mutex_t*) malloc (sizeof(pthread_mutex_t))))
    {
        IFL_LOG_ERROR("Mutex malloc failed!");
        pthread_mutexattr_destroy(&mAttr);
    }
    else
    if ((rc = pthread_mutex_init(mtLock, &mAttr)))
    {
         _what_is_the_problem(111, rc, "Mutex init failed");
         ret = IFL_LOCK_INIT_ERROR;
    }
    else
    if ((rc = pthread_mutexattr_destroy(&mAttr)))
    {
        _what_is_the_problem(111, rc, "Mutex attr destroy failed");
    }
    else
    {
        *lock = (void*)mtLock;
        ret = IFL_SUCCESS;
    }

    return ret;
}

ifl_ret ifl_thread_init (void)
{
    ifl_ret ret = IFL_SUCCESS;
    pthread_mutexattr_t mAttr;
    int rc = -1, idx = 0;

    if ((rc = pthread_mutexattr_init(&mAttr)))
    {
        _what_is_the_problem(111, rc, "Mutex attr init failed");
    }

    rc  = pthread_mutexattr_setrobust(&mAttr,   PTHREAD_MUTEX_ROBUST);
    rc |= pthread_mutexattr_setprotocol(&mAttr, PTHREAD_PRIO_INHERIT);
    rc |= pthread_mutexattr_setpshared(&mAttr,  PTHREAD_PROCESS_PRIVATE);

    if (rc)
    {
        _what_is_the_problem(111, rc, "Mutex attr set failed");
    }

    for ( ;idx < IFL_MAX_CONTEXT; idx++)
    {
        if ((rc = pthread_mutex_init(&mLock[idx], &mAttr)))
        {
            _what_is_the_problem(111, rc, "Mutex init failed");
            ret = IFL_LOCK_INIT_ERROR;
        }
        if ((rc = pthread_spin_init(&sLock[idx], PTHREAD_PROCESS_PRIVATE)))
        {
            _what_is_the_problem(111, rc, "Spin init failed");
            ret = IFL_LOCK_INIT_ERROR;
        }
    }

    if ((rc = pthread_mutexattr_destroy(&mAttr)))
    {
        _what_is_the_problem(111, rc, "Mutex attr destroy failed");
    }

    return ret;
}


ifl_ret ifl_thread_lower_priority (uint8 tID)
{
    int rc = 0;

    if ((rc = _ifl_thread_set_priority(pthread_self(), SCHED_OTHER, IFL_THREAD_LOW_PRIORITY)))
    {
        _what_is_the_problem(tID, rc, "Thread scheduling failed");
    }

    return IFL_SUCCESS;
}

ifl_ret ifl_lose_priority (void)
{
    int rc = 0;

    if ((rc = _ifl_thread_set_priority(pthread_self(), SCHED_OTHER, IFL_THREAD_LOW_PRIORITY)))
    {
        _what_is_the_problem(111, rc, "Thread scheduling failed");
    }

    return IFL_SUCCESS;
}

ifl_ret ifl_thread_reset_priority (uint8 tID)
{
    int rc = 0;

    if ((rc = _ifl_thread_set_priority(pthread_self(), SCHED_RR, IFL_THREAD_DEFAULT_PRIORITY)))
    {
        _what_is_the_problem(tID, rc, "Thread scheduling failed");
    }

    return IFL_SUCCESS;
}

ifl_ret ifl_gain_priority (void)
{
    int rc = 0;

    if ((rc = _ifl_thread_set_priority(pthread_self(), SCHED_RR, IFL_THREAD_DEFAULT_PRIORITY)))
    {
        _what_is_the_problem(111, rc, "Thread scheduling failed");
    }

    return IFL_SUCCESS;
}

ifl_ret ifl_thread_create (thread_prop tPrpty, tfptr_t tFunc, void* tData)
{
    ifl_ret ret = IFL_SUCCESS;
    pthread_attr_t attr;
    pthread_t tID;
    int rc = -1;

    if (!tFunc)
    {
        IFL_LOG_ERROR("Invalid args!");
        return IFL_ARG_INVALID;
    }

    if ((rc = pthread_attr_init (&attr)))
    {
        _what_is_the_problem(111, rc, "Thread attr init failed");
    }

    if (tPrpty & IFL_THRD_PROP_JOIN)
    {
        rc = pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_JOINABLE);
    }
    else // ifl thread default state
    {
        rc = pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);
    }

    /* static settings for now */
    rc |= pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
    rc |= pthread_attr_setscope (&attr, PTHREAD_SCOPE_SYSTEM);
    //rc |= pthread_attr_setschedpolicy (&attr, SCHED_RR);
    //rc |= pthread_attr_setstacksize();

    /*
     * setAffinity
     * atFork
     * cancel defer
     * cancel async
     * clean pop
     * ...
     */

    if (rc)
    {
        _what_is_the_problem(111, rc, "Thread attr set failed");
    }

    if ((rc = pthread_create(&tID, &attr, tFunc, tData)))
    {
        _what_is_the_problem(111, rc, "Thread create failed");
        ret = IFL_THRD_CREATE_ERROR;
    }
    else
    {
        if ((rc = _ifl_thread_set_priority(tID, SCHED_RR, IFL_THREAD_DEFAULT_PRIORITY)))
        {
            _what_is_the_problem(111, rc, "Thread scheduling failed");
        }
    }

    if ((rc = pthread_attr_destroy(&attr)))
    {
        _what_is_the_problem(111, rc, "Thread attr destroy failed");
    }

    return ret;
}

/* Unify the redundant APIs */
ifl_ret ifl_lock (ifl_lock_t* lock, lock_type lType)
{
    ifl_ret ret = IFL_LOCK_ERROR;
    int rc = -1;
    int tID = 111;

    if (!lock)
    {
        IFL_LOG_ERROR("lock entity is null!");
        return ret;
    }

    while(ret!=IFL_SUCCESS)
    {
        switch (lType)
        {
            case IFL_LOCK_TYPE_SPIN:        // Fall through
            case IFL_LOCK_TYPE_SPIN_NO_WAIT:
                    //IFL_LOG_INFO("TrySPIN");
                    rc = pthread_spin_trylock((pthread_spinlock_t*)lock);
                    break;

            case IFL_LOCK_TYPE_SPIN_WAIT:
                    //IFL_LOG_INFO("SPIN");
                    rc = pthread_spin_lock((pthread_spinlock_t*)lock);
                    break;

            case IFL_LOCK_TYPE_MUTEX:       // Fall through
            case IFL_LOCK_TYPE_MUTEX_NO_WAIT:
                    //IFL_LOG_INFO("TryMUTEX");
                    rc = pthread_mutex_trylock((pthread_mutex_t*)lock);
                    break;

            case IFL_LOCK_TYPE_MUTEX_WAIT:
                    //IFL_LOG_INFO("MUTEX");
                    rc = pthread_mutex_lock((pthread_mutex_t*)lock);
                    break;

            case IFL_LOCK_TYPE_SEM:         // Fall through
            default: IFL_LOG_ERROR("[%d] ifl lock type not supported(%d)!", tID, lType);
        }

        if (!rc)
        {
                    //IFL_LOG_INFO("[%d] Lock acquired.", tID);
                    ret = IFL_SUCCESS;
        }
        else
        if (EOWNERDEAD == rc)
        {
                    IFL_LOG_ERROR("[%d] Previously locked thread exited!", tID);
                    if (!pthread_mutex_consistent((pthread_mutex_t*)lock))
                    {
                        IFL_LOG_ERROR("[%d] Lock recovered!", tID);
                    }
                    else
                    {
                        IFL_LOG_ERROR("[%d] Lock recovery failed!", tID);
                        // Fall through with tryunlock?
                    }
                    break;
         }
         else
         if (ENOTRECOVERABLE == rc)
         {
                    IFL_LOG_ERROR("[%d] Lock not recoverable!!", tID);
                    if (!pthread_mutex_destroy((pthread_mutex_t*)lock))
                    {
                        pthread_mutexattr_t mAttr;
                        int lrc = -1;
                        IFL_LOG_ERROR("[%d] Lock destroyed!", tID);
                        IFL_LOG_ERROR("[%d] Lock reiniting!", tID);

                        lrc  = pthread_mutexattr_init(&mAttr);
                        lrc |= pthread_mutexattr_setrobust(&mAttr, PTHREAD_MUTEX_ROBUST);
                        lrc |= pthread_mutex_init((pthread_mutex_t*)lock, &mAttr);

                        if (lrc)
                        {
                            IFL_LOG_ERROR("[%d] Lock reinit failed!", tID);
                        }
                        else
                        {
                            IFL_LOG_ERROR("[%d] Lock reinit done!", tID);
                            if (!pthread_mutex_lock((pthread_mutex_t*)lock))
                            {
                                IFL_LOG_ERROR("[%d] Lock acquired.", tID);
                            }
                            else
                            {
                                IFL_LOG_ERROR("[%d] Lock acquire failed!", tID);
                            }
                        }
                        pthread_mutexattr_destroy(&mAttr);
                    }
                    else
                    {
                        IFL_LOG_ERROR("[%d] Lock destroy failed!", tID);
                    }
                    break;
         }
         else
         if (EBUSY == rc)
         {
                    IFL_LOG_INFO("[%d] Lock is Busy!", tID);
                    ret = IFL_LOCK_BUSY;

                    // yield() here?
                    if (IFL_LOCK_TYPE_MUTEX == lType ||
                        IFL_LOCK_TYPE_SPIN  == lType)
                    {
                        //IFL_LOG_INFO("[%d] yielding...", tID);
                        if (pthread_yield())
                        {
                            /* Should not happen, as this always succeeds in Linux */
                            IFL_LOG_ERROR("[%d] Rejected yielding!", tID);
                        }
                    }
                    else
                    if (IFL_LOCK_TYPE_MUTEX_NO_WAIT == lType ||
                        IFL_LOCK_TYPE_SPIN_NO_WAIT  == lType)
                    {
                        break;
                    }
                    else
                    {
                        IFL_LOG_ERROR("[%d] Lock undefined busy state!", tID);
                    }
         }
         else
         {
                    _what_is_the_problem(tID, rc, "Lock acquire failed");
                    break;
         }
    }

    if (IFL_SUCCESS != ret && IFL_LOCK_BUSY != ret)
    {
        IFL_LOG_ERROR("[%d] Ambiguous lock logic. SHOULD BE FIXED!!!", tID);
    }

    return ret;
}



ifl_ret ifl_thread_lock (uint8 tID, lock_type lType)
{
    ifl_ret ret = IFL_LOCK_ERROR;
    int rc = -1;

    while(ret!=IFL_SUCCESS)
    {
        switch (lType)
        {
            case IFL_LOCK_TYPE_SPIN:        // Fall through
            case IFL_LOCK_TYPE_SPIN_NO_WAIT:
                    //IFL_LOG_INFO("TrySPIN");
                    rc = pthread_spin_trylock(&sLock[tID]);
                    break;

            case IFL_LOCK_TYPE_SPIN_WAIT:
                    //IFL_LOG_INFO("SPIN");
                    rc = pthread_spin_lock(&sLock[tID]);
                    break;

            case IFL_LOCK_TYPE_MUTEX:       // Fall through
            case IFL_LOCK_TYPE_MUTEX_NO_WAIT:
                    //IFL_LOG_INFO("TryMUTEX");
                    rc = pthread_mutex_trylock(&mLock[tID]);
                    break;

            case IFL_LOCK_TYPE_MUTEX_WAIT:
                    //IFL_LOG_INFO("MUTEX");
                    rc = pthread_mutex_lock(&mLock[tID]);
                    break;

            case IFL_LOCK_TYPE_SEM:         // Fall through
            default: IFL_LOG_ERROR("[%d] ifl lock type not supported(%d)!", tID, lType);
        }

        if (!rc)
        {
                    //IFL_LOG_INFO("[%d] Lock acquired.", tID);
                    ret = IFL_SUCCESS;
        }
        else
        if (EOWNERDEAD == rc)
        {
                    IFL_LOG_ERROR("[%d] Previously locked thread exited!", tID);
                    if (!pthread_mutex_consistent(&mLock[tID]))
                    {
                        IFL_LOG_ERROR("[%d] Lock recovered!", tID);
                    }
                    else
                    {
                        IFL_LOG_ERROR("[%d] Lock recovery failed!", tID);
                        // Fall through with tryunlock?
                    }
                    break;
         }
         else
         if (ENOTRECOVERABLE == rc)
         {
                    IFL_LOG_ERROR("[%d] Lock not recoverable!!", tID);
                    if (!pthread_mutex_destroy(&mLock[tID]))
                    {
                        pthread_mutexattr_t mAttr;
                        int lrc = -1;
                        IFL_LOG_ERROR("[%d] Lock destroyed!", tID);
                        IFL_LOG_ERROR("[%d] Lock reiniting!", tID);

                        lrc  = pthread_mutexattr_init(&mAttr);
                        lrc |= pthread_mutexattr_setrobust(&mAttr, PTHREAD_MUTEX_ROBUST);
                        lrc |= pthread_mutex_init(&mLock[tID], &mAttr);

                        if (lrc)
                        {
                            IFL_LOG_ERROR("[%d] Lock reinit failed!", tID);
                        }
                        else
                        {
                            IFL_LOG_ERROR("[%d] Lock reinit done!", tID);
                            if (!pthread_mutex_lock(&mLock[tID]))
                            {
                                IFL_LOG_ERROR("[%d] Lock acquired.", tID);
                            }
                            else
                            {
                                IFL_LOG_ERROR("[%d] Lock acquire failed!", tID);
                            }
                        }
                        pthread_mutexattr_destroy(&mAttr);
                    }
                    else
                    {
                        IFL_LOG_ERROR("[%d] Lock destroy failed!", tID);
                    }
                    break;
         }
         else
         if (EBUSY == rc)
         {
                    IFL_LOG_INFO("[%d] Lock is Busy!", tID);
                    ret = IFL_LOCK_BUSY;

                    // yield() here?
                    if (IFL_LOCK_TYPE_MUTEX == lType ||
                        IFL_LOCK_TYPE_SPIN  == lType)
                    {
                        //IFL_LOG_INFO("[%d] yielding...", tID);
                        if (pthread_yield())
                        {
                            /* Should not happen, as this always succeeds in Linux */
                            IFL_LOG_ERROR("[%d] Rejected yielding!", tID);
                        }
                    }
                    else
                    if (IFL_LOCK_TYPE_MUTEX_NO_WAIT == lType ||
                        IFL_LOCK_TYPE_SPIN_NO_WAIT  == lType)
                    {
                        break;
                    }
                    else
                    {
                        IFL_LOG_ERROR("[%d] Lock undefined busy state!", tID);
                    }
         }
         else
         {
                    _what_is_the_problem(tID, rc, "Lock acquire failed");
                    break;
         }
    }

    if (IFL_SUCCESS != ret && IFL_LOCK_BUSY != ret)
    {
        IFL_LOG_ERROR("[%d] Ambiguous lock logic. SHOULD BE FIXED!!!", tID);
    }

    return ret;
}


ifl_ret ifl_thread_unlock (uint8 tID, lock_type lType)
{
    ifl_ret ret = IFL_UNLOCK_ERROR;
    int rc = -1;

    if (IFL_LOCK_TYPE_SPIN == lType)
    {
        rc = pthread_spin_unlock(&sLock[tID]);
    }
    else
    {
        rc = pthread_mutex_unlock(&mLock[tID]);
    }

    if (!rc)
    {
        //IFL_LOG_INFO("[%d] Lock released.", tID);
        ret = IFL_SUCCESS;
    }
    else
    {
        _what_is_the_problem(tID, rc, "Lock release failed");
    }

    return ret;
}


ifl_ret ifl_unlock (ifl_lock_t* lock, lock_type lType)
{
    ifl_ret ret = IFL_UNLOCK_ERROR;
    int rc = -1;

    if (IFL_LOCK_TYPE_SPIN == lType)
    {
        rc = pthread_spin_unlock((pthread_spinlock_t*)lock);
    }
    else
    {
        rc = pthread_mutex_unlock((pthread_mutex_t*)lock);
    }

    if (!rc)
    {
        //IFL_LOG_INFO("[%d] Lock released.", tID);
        ret = IFL_SUCCESS;
    }
    else
    {
        _what_is_the_problem(111, rc, "Lock release failed");
    }

    return ret;
}


ifl_ret ifl_thread_yield (uint8 tID)
{
    IFL_LOG_INFO("[%d] Yeilding...", tID);
    if (pthread_yield())
    {
        /* Should not happen, as this always succeeds in Linux */
        IFL_LOG_ERROR("[%d] Rejected yielding!", tID);
    }
    return IFL_SUCCESS;
}


ifl_ret ifl_thread_deinit (void)
{
    ifl_ret ret = IFL_SUCCESS;
    uint8   idx = 0;
    int     rc  = 0;

    for ( ;idx < IFL_MAX_CONTEXT; idx++)
    {
        if ((rc = pthread_mutex_destroy(&mLock[idx])))
        {
            _what_is_the_problem(111, rc, "Mutex destroy failed");
            ret = IFL_ERROR;
        }
        if ((rc = pthread_spin_destroy(&sLock[idx])))
        {
            _what_is_the_problem(111, rc, "Spin destroy failed");
            ret = IFL_ERROR;
        }
    }

    return ret;
}


ifl_ret ifl_lock_deinit(ifl_lock_t** lock)
{
    ifl_ret ret = IFL_SUCCESS;
    int     rc  = 0;

    if ((rc = pthread_mutex_destroy((pthread_mutex_t*)*lock)))
    {
        _what_is_the_problem(111, rc, "Mutex destroy failed");
        ret = IFL_ERROR;
    }
    if ((rc = pthread_spin_destroy((pthread_spinlock_t*)*lock)))
    {
        _what_is_the_problem(111, rc, "Spin destroy failed");
        ret = IFL_ERROR;
    }

    free(*lock);
    *lock = NULL;

    return ret;
}
