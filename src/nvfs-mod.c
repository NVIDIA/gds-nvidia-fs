/*
 * Copyright (c) 2022, NVIDIA CORPORATION. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 *
 */
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/module.h>

#include "nvfs-dma.h"
#include "config-host.h"

#ifdef HAVE_MODULE_MUTEX
//exported symbol by kernel module.c
extern struct mutex module_mutex;
#endif
// module entries2
extern struct module_entry modules_list[];

int probe_module_list(void) {
	int i, ret = 0;
	struct module_entry *mod_entry;
	for (i = 0; i < nr_modules(); i++) {
		mod_entry = &modules_list[i];

                //skip pseudo module dependencies
		if (!mod_entry->reg_ksym || !mod_entry->dreg_ksym)
			continue;

		if (mod_entry->found)
			continue;

#ifdef HAVE_MODULE_MUTEX
		mutex_lock(&module_mutex);
#endif
		mod_entry->reg_func = __symbol_get(mod_entry->reg_ksym);
		if (!mod_entry->reg_func) {
#ifdef HAVE_MODULE_MUTEX
			mutex_unlock(&module_mutex);
#endif
			continue;
		}

		mod_entry->dreg_func = __symbol_get(mod_entry->dreg_ksym);
		// We must have complete pairs, otherwise will have inconsistent behavior.
		if (!mod_entry->dreg_func) {
			__symbol_put(mod_entry->reg_ksym);
#ifdef HAVE_MODULE_MUTEX
			mutex_unlock(&module_mutex);
#endif
			mod_entry->reg_func = NULL;
			mod_entry->found = false;
			pr_err("deregister funtion not found %s", mod_entry->dreg_ksym);
			continue;
		}

#ifdef HAVE_MODULE_MUTEX
		mutex_unlock(&module_mutex);
#endif

		// register here. On failure, mark module not found and scan next.
		// Note: on registration failure, it is expected that vendor module
		// MUST set nvfs_dma_ops to null since dereg func will not be invoked
		// on registration failure.
		ret = mod_entry->reg_func(mod_entry->ops);
		if (ret) {
			pr_err("nvfs registration failed for module sym :%s, error :%d\n",
				mod_entry->reg_ksym, ret);

#ifdef HAVE_MODULE_MUTEX
			mutex_lock(&module_mutex);
#endif
			__symbol_put(mod_entry->dreg_ksym);
			mod_entry->dreg_func = NULL;
			__symbol_put(mod_entry->reg_ksym);
			mod_entry->reg_func = NULL;
#ifdef HAVE_MODULE_MUTEX
			mutex_unlock(&module_mutex);
#endif
			mod_entry->found = false;
			ret = 0;
			continue;
		}

		mod_entry->found = true;
		pr_debug("registering :%s\n", mod_entry->reg_ksym);
	}
	return ret;
}

void cleanup_module_list(void) {
	int i = 0;
	struct module_entry *mod_entry;

	for (i = 0; i < nr_modules(); i++) {
		mod_entry = &modules_list[i];

                //skip pseudo module dependencies
		if (!mod_entry->reg_ksym || !mod_entry->dreg_ksym)
			continue;

		// if we obtain owning module info, we must have a ref to the symbol
		if (mod_entry->found) {
			pr_debug("de-registering :%s\n", mod_entry->dreg_ksym);

			mod_entry->found = false;
			mod_entry->dreg_func();

#ifdef HAVE_MODULE_MUTEX
			mutex_lock(&module_mutex);
#endif
			__symbol_put(mod_entry->dreg_ksym);
			mod_entry->dreg_func = NULL;

			__symbol_put(mod_entry->reg_ksym);
			mod_entry->reg_func = NULL;
#ifdef HAVE_MODULE_MUTEX
			mutex_unlock(&module_mutex);
#endif

			// initialized at compile time
			if (!mod_entry->is_mod)
				continue;

		}
	}
}
