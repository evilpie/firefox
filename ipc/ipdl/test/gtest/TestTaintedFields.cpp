/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"

#include "mozilla/_ipdltest/TestTaintedFields.h"

namespace mozilla::_ipdltest {

// Owned by the component that defines PrincipalArgs, and reused by every
// struct that embeds it.
class PrincipalArgsValidatorImpl final : public PrincipalArgsValidator {
 public:
  explicit PrincipalArgsValidatorImpl(const nsCString& aAllowedOrigin)
      : mAllowedOrigin(aAllowedOrigin) {}

  bool ValidateOrigin(const TaintedOrigin& aOrigin) override {
    return aOrigin.spec() == mAllowedOrigin;
  }

 private:
  const nsCString& mAllowedOrigin;
};

class PrincipalOrNoneValidatorImpl final : public PrincipalOrNoneValidator {
 public:
  explicit PrincipalOrNoneValidatorImpl(const nsCString& aAllowedOrigin)
      : mAllowedOrigin(aAllowedOrigin) {}

  bool ValidatePrincipalArgs(Tainted<const PrincipalArgs&> aArgs) override {
    PrincipalArgsValidatorImpl validator(mAllowedOrigin);
    return ValidateTaintedFields(aArgs, validator);
  }

 private:
  const nsCString& mAllowedOrigin;
};

class LoadArgsValidatorImpl final : public LoadArgsValidator {
 public:
  explicit LoadArgsValidatorImpl(const nsCString& aAllowedOrigin)
      : mAllowedOrigin(aAllowedOrigin) {}

  bool ValidateTriggering(const TaintedOrigin& aOrigin) override {
    ++mTriggeringChecks;
    return aOrigin.spec() == mAllowedOrigin;
  }
  bool ValidateLoading(Tainted<const PrincipalArgs&> aArgs) override {
    PrincipalArgsValidatorImpl validator(mAllowedOrigin);
    return ValidateTaintedFields(aArgs, validator);
  }
  bool ValidateRedirectChain(Tainted<const PrincipalArgs&> aArgs) override {
    PrincipalArgsValidatorImpl validator(mAllowedOrigin);
    return ValidateTaintedFields(aArgs, validator);
  }
  bool ValidateTopLevel(Tainted<const PrincipalOrNone&> aTopLevel) override {
    PrincipalOrNoneValidatorImpl validator(mAllowedOrigin);
    return ValidateTaintedFields(aTopLevel, validator);
  }

  nsCString mAllowedOrigin;
  int mTriggeringChecks = 0;
};

struct MissingHookValidator : public LoadArgsValidator {
  bool ValidateTriggering(const TaintedOrigin&) override { return true; }
  bool ValidateLoading(Tainted<const PrincipalArgs&>) override { return true; }
  bool ValidateRedirectChain(Tainted<const PrincipalArgs&>) override {
    return true;
  }
};

static_assert(std::is_abstract_v<MissingHookValidator>);

static LoadArgs MakeLoadArgs(const char* aRedirectOrigin,
                             const char* aTopLevelOrigin) {
  nsTArray<PrincipalArgs> chain;
  chain.AppendElement(PrincipalArgs{TaintedOrigin{"https://a.test"_ns}, 0});
  chain.AppendElement(
      PrincipalArgs{TaintedOrigin{nsCString(aRedirectOrigin)}, 0});
  return LoadArgs{TaintedOrigin{"https://a.test"_ns},
                  Some(PrincipalArgs{TaintedOrigin{"https://a.test"_ns}, 1}),
                  std::move(chain),
                  PrincipalOrNone{PrincipalArgs{
                      TaintedOrigin{nsCString(aTopLevelOrigin)}, 2}},
                  "https://a.test/page"_ns};
}

TEST(IPDLTaintedFields, AllValid)
{
  LoadArgsValidatorImpl validator("https://a.test"_ns);
  Maybe<LoadArgs> args = ValidateTaintedFields(
      Tainted<LoadArgs>(MakeLoadArgs("https://a.test", "https://a.test")),
      validator);
  ASSERT_TRUE(args);
  EXPECT_EQ(args->url(), "https://a.test/page"_ns);
  EXPECT_EQ(args->redirectChain().Length(), 2u);
  EXPECT_EQ(validator.mTriggeringChecks, 1);
}

TEST(IPDLTaintedFields, InvalidArrayElement)
{
  LoadArgsValidatorImpl validator("https://a.test"_ns);
  EXPECT_FALSE(ValidateTaintedFields(
      Tainted<LoadArgs>(MakeLoadArgs("https://evil.test", "https://a.test")),
      validator));
}

TEST(IPDLTaintedFields, InvalidUnionVariant)
{
  LoadArgsValidatorImpl validator("https://a.test"_ns);
  EXPECT_FALSE(ValidateTaintedFields(
      Tainted<LoadArgs>(MakeLoadArgs("https://a.test", "https://evil.test")),
      validator));
}

TEST(IPDLTaintedFields, UntaintedUnionVariant)
{
  LoadArgs args = MakeLoadArgs("https://a.test", "https://a.test");
  args.topLevel() = 0;
  LoadArgsValidatorImpl validator("https://a.test"_ns);
  EXPECT_TRUE(
      ValidateTaintedFields(Tainted<LoadArgs>(std::move(args)), validator));
}

class OriginTreeValidatorImpl final : public OriginTreeValidator,
                                      public OriginTreeNodeValidator {
 public:
  explicit OriginTreeValidatorImpl(const nsCString& aAllowedOrigin)
      : mAllowedOrigin(aAllowedOrigin) {}

  bool ValidateTaintedOrigin(const TaintedOrigin& aOrigin) override {
    return aOrigin.spec() == mAllowedOrigin;
  }
  bool ValidateOriginTreeNode(Tainted<const OriginTreeNode&> aNode) override {
    return ValidateTaintedFields(aNode, *this);
  }
  bool ValidateChildren(Tainted<const OriginTree&> aChild) override {
    return ValidateTaintedFields(aChild, *this);
  }

 private:
  nsCString mAllowedOrigin;
};

TEST(IPDLTaintedFields, Recursive)
{
  auto makeTree = [](const char* aLeafOrigin) {
    nsTArray<OriginTree> inner;
    inner.AppendElement(TaintedOrigin{"https://a.test"_ns});
    inner.AppendElement(TaintedOrigin{nsCString(aLeafOrigin)});
    nsTArray<OriginTree> outer;
    outer.AppendElement(TaintedOrigin{"https://a.test"_ns});
    outer.AppendElement(OriginTreeNode{std::move(inner)});
    return OriginTree{OriginTreeNode{std::move(outer)}};
  };

  OriginTreeValidatorImpl validator("https://a.test"_ns);
  EXPECT_TRUE(ValidateTaintedFields(
      Tainted<OriginTree>(makeTree("https://a.test")), validator));
  EXPECT_FALSE(ValidateTaintedFields(
      Tainted<OriginTree>(makeTree("https://evil.test")), validator));
}

}  // namespace mozilla::_ipdltest
