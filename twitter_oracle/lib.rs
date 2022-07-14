#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use fat_utils::attestation;
use ink_env::AccountId;
use ink_lang as ink;
use ink_prelude::{string::String, vec::Vec};
use pink_extension as pink;

#[ink::trait_definition]
pub trait SubmittableOracle {
    #[ink(message)]
    fn admin(&self) -> AccountId;

    #[ink(message)]
    fn verifier(&self) -> attestation::Verifier;

    #[ink(message)]
    fn attest(&self, arg: String) -> Result<attestation::Attestation, Vec<u8>>;
}

#[pink::contract(env=PinkEnvironment)]
mod twitter_oracle {
    use super::pink;
    use super::SubmittableOracle;
    use pink::logger::{Level, Logger};
    use pink::{http_get, PinkEnvironment};

    use fat_utils::attestation;
    use ink_prelude::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };
    use ink_storage::traits::SpreadAllocate;
    use ink_storage::Mapping;
    use scale::{Decode, Encode};
    use serde::Deserialize;

    use fat_badges::issuable::IssuableRef;

    static LOGGER: Logger = Logger::with_max_level(Level::Info);
    pink::register_logger!(&LOGGER);

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct TwitterOracle {
        admin: AccountId,
        badge_contract_options: Option<(AccountId, u32)>,
        attestation_verifier: attestation::Verifier,
        attestation_generator: attestation::Generator,
        linked_users: Mapping<String, ()>,
    }

    /// Errors that can occur upon calling this contract.
    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        BadOrigin,
        BadgeContractNotSetUp,
        InvalidUrl,
        RequestFailed,
        NoClaimFound,
        InvalidAddressLength,
        InvalidAddress,
        NoPermission,
        InvalidSignature,
        UsernameAlreadyInUse,
        AccountAlreadyInUse,
        FailedToIssueBadge,
        InvalidTweets,
    }

    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;

    impl TwitterOracle {
        #[ink(constructor)]
        pub fn new() -> Self {
            // Create the attestation helpers
            let (generator, verifier) = attestation::create(b"gist-attestation-key");
            // Save sender as the contract admin
            let admin = Self::env().caller();

            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.admin = admin;
                this.badge_contract_options = None;
                this.attestation_generator = generator;
                this.attestation_verifier = verifier;
            })
        }

        /// Sets the downstream badge contract
        ///
        /// Only the admin can call it.
        #[ink(message)]
        pub fn config_issuer(&mut self, contract: AccountId, badge_id: u32) -> Result<()> {
            let caller = self.env().caller();
            if caller != self.admin {
                return Err(Error::BadOrigin);
            }
            // Create a reference to the already deployed FatBadges contract
            self.badge_contract_options = Some((contract, badge_id));
            Ok(())
        }

        /// Redeems a POAP with a signed `attestation`. (callable)
        ///
        /// The attestation must be created by [`attest_gist`] function. After the verification of
        /// the attestation, the the sender account will the linked to a Github username. Then a
        /// POAP redemption code will be allocated to the sender.
        ///
        /// Each blockchain account and github account can only be linked once.
        #[ink(message)]
        pub fn redeem(&mut self, attestation: attestation::Attestation) -> Result<()> {
            // Verify the attestation
            let data: TweetQuote = self
                .attestation_verifier
                .verify_as(&attestation)
                .ok_or(Error::InvalidSignature)?;
            // The caller must be the attested account
            if data.account_id != self.env().caller() {
                pink::warn!("No permission.");
                return Err(Error::NoPermission);
            }
            // The github username can only link to one account
            if self.linked_users.contains(&data.username) {
                pink::warn!("Username alreay in use.");
                return Err(Error::UsernameAlreadyInUse);
            }
            self.linked_users.insert(&data.username, &());
            // Call the badges contract to issue the NFT
            let (contract, id) = self
                .badge_contract_options
                .as_mut()
                .ok_or(Error::BadgeContractNotSetUp)?;

            let badges: &IssuableRef = contract;
            let result = badges.issue(*id, data.account_id);
            pink::warn!("Badges.issue() result = {:?}", result);
            result.or(Err(Error::FailedToIssueBadge))
        }
    }

    impl SubmittableOracle for TwitterOracle {
        // Queries

        /// Attests a Github Gist by the raw file url. (Query only)
        ///
        /// It sends a HTTPS request to the url and extract an address from the claim ("This gist
        /// is owned by address: 0x..."). Once the claim is verified, it returns a signed
        /// attestation with the data `(username, account_id)`.
        ///
        /// The `Err` variant of the result is an encoded `Error` to simplify cross-contract calls.
        /// Particularly, when another contract wants to call us, they may not want to depend on
        /// any special type defined by us (`Error` in this case). So we only return generic types.
        #[ink(message)]
        fn attest(&self, url: String) -> core::result::Result<attestation::Attestation, Vec<u8>> {
            // Verify the URL
            let tweet_url = parse_tweet_url(&url).map_err(|e| e.encode())?;
            // Fetch the tweet content
            // TODO: Add bearer token to the http request -- curl "https://api.twitter.com/2/tweets?ids=1426724855672541191" -H "Authorization: Bearer $BEARER_TOKEN"

            const BEARER_TOKEN: &str = "Bearer AAAAAAAAAAAAAAAAAAAAACXsegEAAAAAmmADAF97nZBWgu1JDKG8ALb6lf8%3DduplCmqITqrQcjsIkovyPPbsu5WY6GNrcjsamf61obQrkJbE44";
            let headers: Vec<(String, String)> =
                vec![("Authorization".into(), BEARER_TOKEN.into())];
            let resposne = http_get!(url, headers);
            if resposne.status_code != 200 {
                return Err(Error::RequestFailed.encode());
            }
            let data: Vec<TweetData> = serde_json_core::from_slice(&resposne.body)
                .map_err(|_| Error::InvalidTweets.encode())?
                .0;
            if !data.is_empty() {
                return Err(Error::InvalidTweets.encode());
            }
            // TODO: multiple Tweets?
            let tweet = data[0].text.clone();
            // Verify the claim and extract the account id
            let account_id = extract_claim(tweet).map_err(|e| e.encode())?;
            let quote = TweetQuote {
                username: tweet_url.username,
                account_id,
            };
            let result = self.attestation_generator.sign(quote);
            Ok(result)
        }

        #[ink(message)]
        fn admin(&self) -> AccountId {
            self.admin.clone()
        }

        /// The attestation verifier
        #[ink(message)]
        fn verifier(&self) -> attestation::Verifier {
            self.attestation_verifier.clone()
        }
    }

    #[derive(Deserialize, Debug)]
    struct TweetData {
        id: String,
        text: String,
    }

    #[derive(PartialEq, Eq, Debug)]
    struct TweetURL {
        // e.g. "https://twitter.com/FokChristopher/status/1546748557595930625"
        username: String, // e.g. FokChristopher
        tweet_id: String, // e.g. 1546748557595930625
    }

    #[derive(Clone, Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct TweetQuote {
        username: String,
        account_id: AccountId,
    }

    fn parse_tweet_url(url: &str) -> Result<TweetURL> {
        let path = url
            .strip_prefix("https://twitter.com/")
            .ok_or(Error::InvalidUrl)?;
        let components: Vec<_> = path.split('/').collect(); // e.g. Vec!["FokChristopher", "status", "1546748557595930625"]
        if components.len() < 3 {
            return Err(Error::InvalidUrl);
        }
        Ok(TweetURL {
            username: components[0].to_string(),
            tweet_id: components[2].to_string(),
        })
    }

    const CLAIM_PREFIX: &str = "This tweet is owned by address: 0x";
    const ADDRESS_LEN: usize = 64;

    /// Extracts the ownerhip of the gist from a claim in the gist body.
    ///
    /// A valid claim must have the statement "This gist is owned by address: 0x..." in `body`. The
    /// address must be the 256 bits public key of the Substrate account in hex.
    ///
    /// - Returns a 256-bit `AccountId` representing the owner account if the claim is valid;
    /// - otherwise returns an [Error].
    fn extract_claim(tweet: String) -> Result<AccountId> {
        let pos = tweet.find(CLAIM_PREFIX).ok_or(Error::NoClaimFound)?;
        let addr: String = tweet
            .chars()
            .skip(pos)
            .skip(CLAIM_PREFIX.len())
            .take(ADDRESS_LEN)
            .collect();
        let addr = addr.as_bytes();
        let account_id = decode_accountid_256(addr)?;
        Ok(account_id)
    }

    /// Decodes a hex string as an 256-bit AccountId32
    fn decode_accountid_256(addr: &[u8]) -> Result<AccountId> {
        use hex::FromHex;
        if addr.len() != ADDRESS_LEN {
            return Err(Error::InvalidAddressLength);
        }
        let bytes = <[u8; 32]>::from_hex(addr).or(Err(Error::InvalidAddress))?;
        Ok(AccountId::from(bytes))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;

        fn default_accounts() -> ink_env::test::DefaultAccounts<PinkEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn can_parse_gist_url() {
            let result =
                parse_tweet_url("https://twitter.com/FokChristopher/status/1546748557595930625");
            assert_eq!(
                result,
                Ok(TweetURL {
                    username: "FokChristopher".to_string(),
                    tweet_id: "1546748557595930625".to_string()
                })
            );
            let err = parse_tweet_url("http://example.com");
            assert_eq!(err, Err(Error::InvalidUrl));
        }

        #[ink::test]
        fn can_decode_claim() {
            let ok = extract_claim("...This tweet is owned by address: 0x0123456789012345678901234567890123456789012345678901234567890123...".to_string());
            assert_eq!(
                ok,
                decode_accountid_256(
                    b"0123456789012345678901234567890123456789012345678901234567890123"
                )
            );
            // Bad cases
            assert_eq!(
                extract_claim("This gist is owned by".to_string()),
                Err(Error::NoClaimFound),
            );
            assert_eq!(
                extract_claim("This gist is owned by address: 0xAB".to_string()),
                Err(Error::InvalidAddressLength),
            );
            assert_eq!(
                extract_claim("This gist is owned by address: 0xXX23456789012345678901234567890123456789012345678901234567890123".to_string()),
                Err(Error::InvalidAddress),
            );
        }

        #[ink::test]
        fn end_to_end() {
            use pink_extension::chain_extension::{mock, HttpResponse};
            fat_utils::test_helper::mock_all();

            // Test accounts
            let accounts = default_accounts();

            use fat_badges::issuable::mock_issuable;
            use openbrush::traits::mock::{Addressable, SharedCallStack};

            let stack = SharedCallStack::new(accounts.alice);
            mock_issuable::using(stack.clone(), || {
                // Deploy a FatBadges contract
                let badges = mock_issuable::deploy(fat_badges::FatBadges::new());

                // Construct our contract (deployed by `accounts.alice` by default)
                let contract = Addressable::create_native(1, TwitterOracle::new(), stack);

                // Create a badge and add the oracle contract as its issuer
                let id = badges
                    .call_mut()
                    .new_badge("test-badge".to_string())
                    .unwrap();
                assert!(badges
                    .call_mut()
                    .add_code(id, vec!["code1".to_string(), "code2".to_string()])
                    .is_ok());
                assert!(badges.call_mut().add_issuer(id, contract.id()).is_ok());
                // Tell the oracle the badges are ready to issue
                assert!(contract.call_mut().config_issuer(badges.id(), id).is_ok());

                // Generate an attestation
                //
                // Mock a http request first (the 256 bits account id is the pubkey of Alice)
                mock::mock_http_request(|_| {
                    HttpResponse::ok(b"This gist is owned by address: 0x0101010101010101010101010101010101010101010101010101010101010101".to_vec())
                });
                let result = contract.call().attest("https://gist.githubusercontent.com/h4x3rotab/0cabeb528bdaf30e4cf741e26b714e04/raw/620f958fb92baba585a77c1854d68dc986803b4e/test%2520gist".to_string());
                assert!(result.is_ok());

                let attestation = result.unwrap();
                let data: TweetQuote = Decode::decode(&mut &attestation.data[..]).unwrap();
                assert_eq!(data.username, "h4x3rotab");
                assert_eq!(data.account_id, accounts.alice);

                // Before redeem
                assert!(badges.call().get(id).is_err());

                // Redeem and check if the contract as the code distributed
                contract
                    .call_mut()
                    .redeem(attestation)
                    .expect("Should be able to issue badge");
                assert_eq!(badges.call().get(id), Ok("code1".to_string()));
            });
        }
    }
}
