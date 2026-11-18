/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"

#include "mozilla/_ipdltest/TestTaintedFields.h"

namespace mozilla::_ipdltest {

// Owned by the component that defines PrincipalArgs, and reused by every
// struct that embeds it.
struct PrincipalArgsValidatorImpl {
  const nsCString& mAllowedOrigin;

  bool ValidateOrigin(const TaintedOrigin& aOrigin) {
    return aOrigin.spec() == mAllowedOrigin;
  }
};

struct PrincipalOrNoneValidatorImpl {
  const nsCString& mAllowedOrigin;

  PrincipalArgsValidatorImpl PrincipalArgs() { return {mAllowedOrigin}; }
};

struct LoadArgsValidatorImpl {
  nsCString mAllowedOrigin;
  int mTriggeringChecks = 0;

  bool ValidateTriggering(const TaintedOrigin& aOrigin) {
    ++mTriggeringChecks;
    return aOrigin.spec() == mAllowedOrigin;
  }
  PrincipalArgsValidatorImpl Loading() { return {mAllowedOrigin}; }
  PrincipalArgsValidatorImpl RedirectChain() { return {mAllowedOrigin}; }
  PrincipalOrNoneValidatorImpl TopLevel() { return {mAllowedOrigin}; }
};

static_assert(ValidatesLoadArgs<LoadArgsValidatorImpl>);

struct MissingHookValidator {
  bool ValidateTriggering(const TaintedOrigin&) { return true; }
  PrincipalArgsValidatorImpl Loading();
  PrincipalArgsValidatorImpl RedirectChain();
};

static_assert(!ValidatesLoadArgs<MissingHookValidator>);

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
  LoadArgsValidatorImpl validator{"https://a.test"_ns};
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
  EXPECT_FALSE(ValidateTaintedFields(
      Tainted<LoadArgs>(MakeLoadArgs("https://evil.test", "https://a.test")),
      LoadArgsValidatorImpl{"https://a.test"_ns}));
}

TEST(IPDLTaintedFields, InvalidUnionVariant)
{
  EXPECT_FALSE(ValidateTaintedFields(
      Tainted<LoadArgs>(MakeLoadArgs("https://a.test", "https://evil.test")),
      LoadArgsValidatorImpl{"https://a.test"_ns}));
}

TEST(IPDLTaintedFields, UntaintedUnionVariant)
{
  LoadArgs args = MakeLoadArgs("https://a.test", "https://a.test");
  args.topLevel() = 0;
  EXPECT_TRUE(
      ValidateTaintedFields(Tainted<LoadArgs>(std::move(args)),
                            LoadArgsValidatorImpl{"https://a.test"_ns}));
}

struct OriginTreeValidatorImpl {
  nsCString mAllowedOrigin;

  bool ValidateTaintedOrigin(const TaintedOrigin& aOrigin) {
    return aOrigin.spec() == mAllowedOrigin;
  }
  OriginTreeValidatorImpl& OriginTreeNode() { return *this; }
  OriginTreeValidatorImpl& Children() { return *this; }
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

  EXPECT_TRUE(
      ValidateTaintedFields(Tainted<OriginTree>(makeTree("https://a.test")),
                            OriginTreeValidatorImpl{"https://a.test"_ns}));
  EXPECT_FALSE(
      ValidateTaintedFields(Tainted<OriginTree>(makeTree("https://evil.test")),
                            OriginTreeValidatorImpl{"https://a.test"_ns}));
}

}  // namespace mozilla::_ipdltest
