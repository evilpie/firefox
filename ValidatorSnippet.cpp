namespace mozilla {
namespace net {
// Validates the tainted members of |LoadInfoArgs|.
class LoadInfoArgsValidator {
 public:
  virtual bool ValidateRequestingPrincipal(::nsIPrincipal* aRequestingPrincipal) = 0;
  virtual bool ValidateTriggeringPrincipal(::nsIPrincipal* aTriggeringPrincipal) = 0;
  virtual bool ValidatePrincipalToInherit(::nsIPrincipal* aPrincipalToInherit) = 0;
  virtual bool ValidateTopLevelPrincipal(::nsIPrincipal* aTopLevelPrincipal) = 0;
  virtual bool ValidateRedirectChainIncludingInternalRedirects(mozilla::Tainted<const ::mozilla::net::RedirectHistoryEntryInfo&> aRedirectChainIncludingInternalRedirects) = 0;
  virtual bool ValidateRedirectChain(mozilla::Tainted<const ::mozilla::net::RedirectHistoryEntryInfo&> aRedirectChain) = 0;
  virtual bool ValidateClientInfo(const ::mozilla::dom::IPCClientInfo& aClientInfo) = 0;
  virtual bool ValidateReservedClientInfo(const ::mozilla::dom::IPCClientInfo& aReservedClientInfo) = 0;
  virtual bool ValidateInitialClientInfo(const ::mozilla::dom::IPCClientInfo& aInitialClientInfo) = 0;
  virtual bool ValidateInterceptionInfo(mozilla::Tainted<const ::mozilla::net::InterceptionInfoArg&> aInterceptionInfo) = 0;
  virtual bool ValidateAncestorOrigins(::nsIPrincipal* aAncestorOrigins) = 0;

 protected:
  virtual ~LoadInfoArgsValidator() = default;
};

// Returns whether every tainted member of |aTainted| is valid according
// to |aValidator|.
[[nodiscard]] bool ValidateTaintedFields(
    mozilla::Tainted<const LoadInfoArgs&> aTainted, LoadInfoArgsValidator& aValidator);

// Validates every tainted member of |aTainted| using |aValidator|, and
// returns the untainted value if all of them are valid.
[[nodiscard]] mozilla::Maybe<LoadInfoArgs> ValidateTaintedFields(
    mozilla::Tainted<LoadInfoArgs>&& aTainted, LoadInfoArgsValidator& aValidator);
} // namespace net
} // namespace mozilla

// In NeckoChannelParams.cpp:
namespace mozilla {
namespace net {
bool ValidateTaintedFields(
    mozilla::Tainted<const LoadInfoArgs&> aTainted, LoadInfoArgsValidator& aValidator) {
  const LoadInfoArgs& value = aTainted.Coerce();
  {
    if (!aValidator.ValidateRequestingPrincipal(value.requestingPrincipal())) {
      return false;
    }
  }
  {
    if (!aValidator.ValidateTriggeringPrincipal(value.triggeringPrincipal())) {
      return false;
    }
  }
  {
    if (!aValidator.ValidatePrincipalToInherit(value.principalToInherit())) {
      return false;
    }
  }
  {
    if (!aValidator.ValidateTopLevelPrincipal(value.topLevelPrincipal())) {
      return false;
    }
  }
  {
    for (const auto& e0 : value.redirectChainIncludingInternalRedirects()) {
      if (!aValidator.ValidateRedirectChainIncludingInternalRedirects(mozilla::Tainted<const ::mozilla::net::RedirectHistoryEntryInfo&>(e0))) {
        return false;
      }
    }
  }
  {
    for (const auto& e0 : value.redirectChain()) {
      if (!aValidator.ValidateRedirectChain(mozilla::Tainted<const ::mozilla::net::RedirectHistoryEntryInfo&>(e0))) {
        return false;
      }
    }
  }
  {
    if (const auto& e0 = value.clientInfo()) {
      if (!aValidator.ValidateClientInfo(*e0)) {
        return false;
      }
    }
  }
  {
    if (const auto& e0 = value.reservedClientInfo()) {
      if (!aValidator.ValidateReservedClientInfo(*e0)) {
        return false;
      }
    }
  }
  {
    if (const auto& e0 = value.initialClientInfo()) {
      if (!aValidator.ValidateInitialClientInfo(*e0)) {
        return false;
      }
    }
  }
  {
    if (const auto& e0 = value.interceptionInfo()) {
      if (!aValidator.ValidateInterceptionInfo(mozilla::Tainted<const ::mozilla::net::InterceptionInfoArg&>(*e0))) {
        return false;
      }
    }
  }
  {
    for (const auto& e0 : value.ancestorOrigins()) {
      if (!aValidator.ValidateAncestorOrigins(e0)) {
        return false;
      }
    }
  }
  return true;
}

mozilla::Maybe<LoadInfoArgs> ValidateTaintedFields(
    mozilla::Tainted<LoadInfoArgs>&& aTainted, LoadInfoArgsValidator& aValidator) {
  LoadInfoArgs& value = aTainted.Coerce();
  if (!ValidateTaintedFields(mozilla::Tainted<const LoadInfoArgs&>(value), aValidator)) {
    return mozilla::Nothing();
  }
  return mozilla::Some(std::move(value));
}
} // namespace net
} // namespace mozilla
