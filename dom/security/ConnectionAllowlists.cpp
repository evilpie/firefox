/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ConnectionAllowlists.h"

#include <utility>

#include "mozilla/Logging.h"
#include "mozilla/net/SFV.h"
#include "nsContentUtils.h"
#include "nsIURI.h"
#include "nsString.h"

using namespace mozilla;

static LazyLogModule sConnectionAllowlistsLog("ConnectionAllowlists");
#define LOG(fmt, ...) \
  MOZ_LOG_FMT(sConnectionAllowlistsLog, LogLevel::Debug, fmt, ##__VA_ARGS__)

namespace mozilla::dom {

// https://wicg.github.io/connection-allowlists/#abstract-opdef-parse-a-connection-allowlist-header
/* static */
Maybe<ConnectionAllowlists::Allowlist>
ConnectionAllowlists::ParseConnectionAllowlistHeader(const nsACString& aHeader,
                                                     nsIURI* aResponseURI,
                                                     Disposition aDisposition) {
  if (aHeader.IsEmpty()) {
    return Nothing();
  }

  // 1. If list's size is 0, return null.
  auto list = net::SFV::ParseList(aHeader);
  if (!list.IsValid() || list.Length() == 0) {
    LOG("Failed to parse header as a structured field list.");
    return Nothing();
  }

  // 2. If list[0] is not an inner list, return null.
  auto innerList = list.GetInnerListAt(0);
  if (!innerList.IsValid()) {
    LOG("First list member is not an inner list.");
    return Nothing();
  }

  // 3. Let allowlist be a Connection Allowlist whose disposition is
  // disposition.
  ConnectionAllowlists::Allowlist allowlist;
  allowlist.mDisposition = aDisposition;

  // 4. For each item in list[0]:
  size_t length = innerList.Length();
  for (size_t i = 0; i < length; i++) {
    auto item = innerList.GetItemAt(i);
    if (!item.IsValid()) {
      continue;
    }

    // 4.1. Let serialized pattern be null.
    nsAutoCString serializedPattern;

    nsAutoCString token;
    if (NS_SUCCEEDED(item.GetValue<net::SFV::Token>(token))) {
      // 4.2. If item is the token `response-origin`:
      if (!token.EqualsLiteral("response-origin")) {
        // Any other token leaves serialized pattern null, so 4.4 continues.
        continue;
      }

      // 4.2.1. Set serialized pattern to the ASCII serialization of
      // response-url's origin.
      if (aResponseURI) {
        nsContentUtils::GetWebExposedOriginSerialization(aResponseURI,
                                                         serializedPattern);
      }
    } else if (NS_FAILED(
                   item.GetValue<net::SFV::SFVString>(serializedPattern))) {
      // 4.3. If item is a string, set serialized pattern to item.
      // (Neither a token nor a string leaves serialized pattern null.)
      continue;
    }

    // 4.4. If serialized pattern is null, continue.
    if (serializedPattern.IsEmpty()) {
      continue;
    }

    // 4.5. Let URL pattern be the result of executing build a URL pattern from
    // an HTTP structured field value given serialized pattern with null as the
    // base URL. If this step throws an error, continue.
    UrlPatternGlue pattern = nullptr;
    UrlPatternOptions options{};
    if (!urlpattern_parse_pattern_from_string(&serializedPattern, nullptr,
                                              options, &pattern)) {
      LOG("Failed to parse URLPattern: {}", serializedPattern);
      continue;
    }

    // 4.6. Append URL pattern to allowlist's allowlist.
    allowlist.mPatterns.AppendElement(UrlPattern(std::move(pattern)));
  }

  // 5. For each key → value in list[0]'s parameters:
  nsAutoCString paramValue;

  // 5.1. If key is `report-to` and value is a token, set allowlist's reporting
  // endpoint to value.
  if (NS_SUCCEEDED(
          innerList.GetParam<net::SFV::Token>("report-to"_ns, paramValue))) {
    allowlist.mReportingEndpoint = paramValue;
  }

  // 5.2. If key is `redirects` and value is a token: If value is `block`, set
  // redirects to block. Else, set redirects to allow.
  if (NS_SUCCEEDED(
          innerList.GetParam<net::SFV::Token>("redirects"_ns, paramValue))) {
    allowlist.mRedirects = paramValue.EqualsLiteral("block")
                               ? ConnectionAllowlists::Redirects::Block
                               : ConnectionAllowlists::Redirects::Allow;
  }

  // 5.3. If key is `webrtc` and value is a token: If value is `block`, set
  // webrtc to block. Else, set webrtc to allow.
  if (NS_SUCCEEDED(
          innerList.GetParam<net::SFV::Token>("webrtc"_ns, paramValue))) {
    allowlist.mWebRTC = paramValue.EqualsLiteral("block")
                            ? ConnectionAllowlists::WebRTC::Block
                            : ConnectionAllowlists::WebRTC::Allow;
  }

  // 6. Return allowlist.
  return Some(std::move(allowlist));
}

/* static */
nsresult ConnectionAllowlists::ParseHeaders(const nsACString& aHeader,
                                            const nsACString& aReportOnlyHeader,
                                            nsIURI* aResponseURI,
                                            ConnectionAllowlists** aResult) {
  *aResult = nullptr;

  Maybe<Allowlist> enforcement = ParseConnectionAllowlistHeader(
      aHeader, aResponseURI, Disposition::Enforce);
  Maybe<Allowlist> reportOnly = ParseConnectionAllowlistHeader(
      aReportOnlyHeader, aResponseURI, Disposition::Report);

  if (enforcement.isNothing() && reportOnly.isNothing()) {
    return NS_OK;
  }

  RefPtr<ConnectionAllowlists> allowlists = new ConnectionAllowlists();
  allowlists->mEnforcement = std::move(enforcement);
  allowlists->mReportOnly = std::move(reportOnly);
  allowlists.forget(aResult);
  return NS_OK;
}

}  // namespace mozilla::dom

#undef LOG
