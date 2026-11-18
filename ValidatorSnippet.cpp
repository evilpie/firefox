namespace mozilla {
namespace net {

// Hooks needed to validate the tainted members of |LoadInfoArgs|.
template <typename V>
concept ValidatesLoadInfoArgs = requires(V& aValidator, ::nsIPrincipal* aRequestingPrincipal, ::nsIPrincipal* aTriggeringPrincipal, ::nsIPrincipal* aPrincipalToInherit, ::nsIPrincipal* aTopLevelPrincipal, const ::mozilla::dom::IPCClientInfo& aClientInfo, const ::mozilla::dom::IPCClientInfo& aReservedClientInfo, const ::mozilla::dom::IPCClientInfo& aInitialClientInfo, ::nsIPrincipal* aAncestorOrigins) {
  { aValidator.ValidateRequestingPrincipal(aRequestingPrincipal) } -> std::same_as<bool>;
  { aValidator.ValidateTriggeringPrincipal(aTriggeringPrincipal) } -> std::same_as<bool>;
  { aValidator.ValidatePrincipalToInherit(aPrincipalToInherit) } -> std::same_as<bool>;
  { aValidator.ValidateTopLevelPrincipal(aTopLevelPrincipal) } -> std::same_as<bool>;
  { aValidator.RedirectChainIncludingInternalRedirects() } -> ::mozilla::net::ValidatesRedirectHistoryEntryInfo;
  { aValidator.RedirectChain() } -> ::mozilla::net::ValidatesRedirectHistoryEntryInfo;
  { aValidator.ValidateClientInfo(aClientInfo) } -> std::same_as<bool>;
  { aValidator.ValidateReservedClientInfo(aReservedClientInfo) } -> std::same_as<bool>;
  { aValidator.ValidateInitialClientInfo(aInitialClientInfo) } -> std::same_as<bool>;
  { aValidator.InterceptionInfo() } -> ::mozilla::net::ValidatesInterceptionInfoArg;
  { aValidator.ValidateAncestorOrigins(aAncestorOrigins) } -> std::same_as<bool>;
};

template <ValidatesLoadInfoArgs V>
[[nodiscard]] bool ValidateTaintedFieldsInPlace(LoadInfoArgs& aValue, V& aValidator) {
  {
    if (!aValidator.ValidateRequestingPrincipal(aValue.requestingPrincipal())) {
      return false;
    }
  }
  {
    if (!aValidator.ValidateTriggeringPrincipal(aValue.triggeringPrincipal())) {
      return false;
    }
  }
  {
    if (!aValidator.ValidatePrincipalToInherit(aValue.principalToInherit())) {
      return false;
    }
  }
  {
    if (!aValidator.ValidateTopLevelPrincipal(aValue.topLevelPrincipal())) {
      return false;
    }
  }
  {
    auto&& sub = aValidator.RedirectChainIncludingInternalRedirects();
    for (auto& e0 : aValue.redirectChainIncludingInternalRedirects()) {
      if (!ValidateTaintedFieldsInPlace(e0, sub)) {
        return false;
      }
    }
  }
  {
    auto&& sub = aValidator.RedirectChain();
    for (auto& e0 : aValue.redirectChain()) {
      if (!ValidateTaintedFieldsInPlace(e0, sub)) {
        return false;
      }
    }
  }
  {
    if (auto& e0 = aValue.clientInfo()) {
      if (!aValidator.ValidateClientInfo(*e0)) {
        return false;
      }
    }
  }
  {
    if (auto& e0 = aValue.reservedClientInfo()) {
      if (!aValidator.ValidateReservedClientInfo(*e0)) {
        return false;
      }
    }
  }
  {
    if (auto& e0 = aValue.initialClientInfo()) {
      if (!aValidator.ValidateInitialClientInfo(*e0)) {
        return false;
      }
    }
  }
  {
    auto&& sub = aValidator.InterceptionInfo();
    if (auto& e0 = aValue.interceptionInfo()) {
      if (!ValidateTaintedFieldsInPlace(*e0, sub)) {
        return false;
      }
    }
  }
  {
    for (auto& e0 : aValue.ancestorOrigins()) {
      if (!aValidator.ValidateAncestorOrigins(e0)) {
        return false;
      }
    }
  }
  return true;
}

// Validates every tainted member of |aTainted| using |aValidator|, and
// returns the untainted value if all of them are valid.
template <ValidatesLoadInfoArgs V>
[[nodiscard]] mozilla::Maybe<LoadInfoArgs> ValidateTaintedFields(
    mozilla::Tainted<LoadInfoArgs>&& aTainted, V&& aValidator) {
  LoadInfoArgs& value = aTainted.Coerce();
  if (!ValidateTaintedFieldsInPlace(value, aValidator)) {
    return mozilla::Nothing();
  }
  return mozilla::Some(std::move(value));
}
} // namespace net
} // namespace mozilla