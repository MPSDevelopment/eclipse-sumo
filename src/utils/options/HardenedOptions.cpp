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
/// @file    HardenedOptions.cpp
/// @date    Nov 2026
///
// Allowlist of options for hardened builds
/****************************************************************************/
#include <config.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include <utils/common/UtilExceptions.h>
#include <utils/xml/SUMOKeyring.h>
#include "Option.h"
#include "OptionsCont.h"
#include "HardenedOptions.h"


namespace {

// What DARTS passes. Add an option here only on purpose, after checking that it cannot write a file or expose
// the decrypted input.
const std::set<std::string> ALLOWED = {
    "configuration-file", "net-file", "route-files", "additional-files",
    "remote-port", "num-clients",
    "step-length", "begin", "end", "seed", "random",
    "time-to-teleport", "collision.action", "collision.check-junctions", "default.speeddev",
    "ignore-route-errors", "max-depart-delay",
    "no-step-log", "no-warnings", "verbose", "duration-log.disable",
    "log", "message-log", "error-log",
};


bool
allowedValue(const std::string& name, const Option* option) {
    if (name == "num-clients") {
        return option->getInt() == 1;
    }
    if (name == "verbose") {
        return !option->getBool();
    }
    return true;
}

}


void
HardenedOptions::check(const OptionsCont& oc) {
    if (!SUMOKeyring::isRequired()) {
        return;
    }
    // synonyms share one Option, so decide per Option over all of its names
    std::map<const Option*, std::vector<std::string> > names;
    for (auto it = oc.begin(); it != oc.end(); ++it) {
        names[it->second].push_back(it->first);
    }
    for (const auto& item : names) {
        const Option* const option = item.first;
        if (!option->isSet() || option->isDefault()) {
            continue;
        }
        std::string allowedName;
        for (const std::string& name : item.second) {
            if (ALLOWED.count(name) > 0) {
                allowedName = name;
            }
        }
        if (allowedName.empty()) {
            throw ProcessError("Option '--" + item.second.front() + "' is not allowed in this hardened build.");
        }
        if (!allowedValue(allowedName, option)) {
            throw ProcessError("Option '--" + allowedName + "' may not be set to '" + option->getValueString()
                               + "' in this hardened build.");
        }
    }
}
