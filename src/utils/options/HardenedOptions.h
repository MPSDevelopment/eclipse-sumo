/****************************************************************************/
// Eclipse SUMO, Simulation of Urban MObility; see https://eclipse.dev/sumo
// Copyright (C) 2026 MPS Development.
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0/
// This Source Code may also be made available under the following Secondary
// Licenses when the conditions for such availability set forth in the Eclipse
// Public License 2.0 are satisfied: GNU General Public License, version 2
// or later which is available at
// https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
// SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
/****************************************************************************/
/// @file    HardenedOptions.h
/// @date    Nov 2026
///
// Allowlist of options for hardened builds
/****************************************************************************/
#pragma once
#include <config.h>


class OptionsCont;


/**
 * @class HardenedOptions
 * @brief In a hardened build (SUMOKeyring::isRequired()), allows only the options DARTS needs
 *
 * Every option set to a non-default value, on the command line or in a configuration file, must be on the
 * allowlist (HardenedOptions.cpp); num-clients may only be 1 and verbose only off. Anything else, including
 * options a later upstream version adds, makes sumo exit with an error.
 */
class HardenedOptions {
public:
    /// @throw ProcessError naming the first refused option
    static void check(const OptionsCont& oc);
};
