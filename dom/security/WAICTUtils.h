/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef WAICTUtils_h
#define WAICTUtils_h

#include "nsStringFwd.h"

class nsISFVDictionary;

namespace mozilla {

namespace waict {

nsresult ParseManifest(nsISFVDictionary* aDict, nsACString& outManifest);

nsresult ParseMaxAge(nsISFVDictionary* aDict, uint64_t* outMaxAge);

nsresult ParseMode(nsISFVDictionary* aDict, bool* outEnforce);

}  // namespace waict

}  // namespace mozilla

#endif  // WAICTUtils_h
