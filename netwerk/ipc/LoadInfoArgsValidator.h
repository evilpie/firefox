/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_LoadInfoArgsValidator_h
#define mozilla_net_LoadInfoArgsValidator_h

#include "mozilla/Maybe.h"
#include "mozilla/Tainting.h"
#include "mozilla/net/NeckoChannelParams.h"

namespace mozilla::dom {
class LoadedOriginSet;
}

namespace mozilla::net {

/**
 * Validates a LoadInfoArgs received from a content process, whose loaded
 * origins are |aLoadedOrigins|.
 */
Maybe<LoadInfoArgs> ValidateLoadInfoArgsFromContent(
    Tainted<LoadInfoArgs>&& aArgs, dom::LoadedOriginSet* aLoadedOrigins);

}  // namespace mozilla::net

#endif  // mozilla_net_LoadInfoArgsValidator_h
