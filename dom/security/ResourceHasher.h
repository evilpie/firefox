#ifndef mozilla_dom_ResourceHasher_h
#define mozilla_dom_ResourceHasher_h

#include "nsCOMPtr.h"
#include "nsICryptoHash.h"
#include "nsString.h"

namespace mozilla {
namespace dom {

class ResourceHasher final {
 public:
  NS_INLINE_DECL_REFCOUNTING(ResourceHasher)

  // Create a hasher with specified algorithm (nsICryptoHash::SHA256, etc.)
  static already_AddRefed<ResourceHasher> Init(uint32_t aAlgorithm);

  // Update hash with new data
  nsresult Update(const uint8_t* aData, uint32_t aLength);

  // Finalize and get the hash as base64 string
  nsresult Finish();

  const nsACString& GetHash() const { return mComputedHash; }

 private:
  explicit ResourceHasher(nsICryptoHash* aCrypto);
  ~ResourceHasher() = default;

  nsCOMPtr<nsICryptoHash> mCrypto;
  nsCString mComputedHash;
  bool mFinalized;
};

}  // namespace dom
}  // namespace mozilla

#endif  // mozilla_dom_ResourceHasher_h