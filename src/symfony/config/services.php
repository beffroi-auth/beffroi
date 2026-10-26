<?php

declare(strict_types=1);

use Beffroi\Bundle\Http\LoginAddresses;
use Beffroi\Bundle\Saml\UpstreamDiscovery;
use Beffroi\Core\Port\UpstreamProvidersInterface;
use Beffroi\Bundle\Saml\SamlUpstreamProviders;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Bundle\Command\DoctorCommand;
use Beffroi\Bundle\Doctor\NotificationsLanePatience;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Application\Secret\UserCodeDrawer;
use Beffroi\Core\Port\RandomnessInterface;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Bundle\Account\ApplicationHoldings;
use Beffroi\Bundle\Ciba\QueuedPendingApprovalNotifier;
use Beffroi\Bundle\Cache\SeenOnce;
use Beffroi\Bundle\Client\ClientAssertionReplayGuard;
use Beffroi\Bundle\Client\SoftwareStatementReplayGuard;
use Beffroi\Bundle\Trust\IssuerAssertionReplayGuard;
use Beffroi\Bundle\Client\RequestObjectReplayGuard;
use Beffroi\Bundle\Client\ClientJwksCache;
use Beffroi\Bundle\Client\ClientJwksFetcher;
use Beffroi\Bundle\Client\RequestObjectFetcher;
use Beffroi\Bundle\Client\SectorIdentifierDocumentFetcher;
use Beffroi\Bundle\Doctrine\Listener\ClientResolver;
use Beffroi\Bundle\Doctrine\DoctrineAtomicWrites;
use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\PageOfRows;
use Beffroi\Bundle\Doctrine\Repository\DoctrineAccessTokenRepository;
use Beffroi\Bundle\Doctrine\Repository\BoundedDelete;
use Beffroi\Bundle\Doctrine\Repository\DoctrineAuthenticationSessionRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrineAuthorizationCodeRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrineClientRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrineInitialAccessTokenRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrineConsentRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrineCredentialRepository;
use Beffroi\Core\Port\EnrolmentTicketRepositoryInterface;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketRedemption;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use Beffroi\Bundle\Http\PresentedEnrolmentTicket;
use Beffroi\Bundle\Doctrine\Repository\DoctrineEnrolmentTicketRepository;
use Beffroi\Core\Port\TenantRepositoryInterface;
use Beffroi\Core\Port\CanForgetCredentialsInterface;
use Beffroi\Core\Application\Tenant\TenantHardening;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Bundle\Http\OfferedLogins;
use Beffroi\Bundle\Doctrine\Repository\DoctrineTenantRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrineInteractionRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrinePairwiseSubjectRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrinePushedAuthorizationRecordRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrineBackchannelAuthenticationRecordRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrineDeviceAuthorizationRecordRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrineRefreshTokenRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrineLinkedIdentityRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrineGroupMembershipRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrineGroupRepository;
use Beffroi\Bundle\Doctrine\Repository\DoctrinePersonalArchiveRepository;
use Beffroi\Bundle\Http\Account\ArchiveSection;
use Beffroi\Bundle\Archive\ZipArchiveContainer;
use Beffroi\Bundle\Http\ArchivePage;
use Beffroi\Core\Application\Archive\ArchiveAssembly;
use Beffroi\Core\Application\Archive\ArchiveDisposal;
use Beffroi\Core\Application\Archive\ArchiveHandout;
use Beffroi\Core\Port\ArchiveContainerInterface;
use Beffroi\Core\Application\Archive\ArchiveRequest;
use Beffroi\Core\Application\Archive\ArchiveRetention;
use Beffroi\Core\Application\Archive\Chapter\CredentialsChapter;
use Beffroi\Core\Application\Archive\Chapter\GroupsChapter;
use Beffroi\Core\Application\Archive\Chapter\JournalChapter;
use Beffroi\Core\Application\Archive\Chapter\LinkedIdentitiesChapter;
use Beffroi\Core\Application\Archive\Chapter\ProfileChapter;
use Beffroi\Core\Application\Archive\Chapter\SessionsChapter;
use Beffroi\Core\Port\GroupMembershipRepositoryInterface;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Core\Port\LinkedIdentitiesOfAPersonInterface;
use Beffroi\Core\Port\PersonalArchiveRepositoryInterface;
use Beffroi\Oidc\Application\Archive\ConsentsChapter;
use Beffroi\Bundle\Doctrine\Repository\DoctrineUserRepository;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Doctrine\TenantSynchronizer;
use Beffroi\Bundle\Dpop\CachedDpopNonce;
use Beffroi\Bundle\Dpop\CachedDpopProofReplayGuard;
use Beffroi\Bundle\EndSession\FrontChannelLogoutRenderer;
use Beffroi\Bundle\EndSession\LogoutChannels;
use Beffroi\Bundle\EndSession\LogoutTokenDeliveryBudget;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\AskedPage;
use Beffroi\Bundle\Http\AskedPeriod;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Bundle\Http\AccountHomePage;
use Beffroi\Bundle\Http\Account\AccountSections;
use Beffroi\Bundle\Http\Account\BreachedPasswordDemand;
use Beffroi\Bundle\Http\Account\RecentProofListener;
use Beffroi\Bundle\Http\Account\PasskeysSection;
use Beffroi\Bundle\Http\Account\ProfileSection;
use Beffroi\Bundle\Http\Account\ApprovalsSection;
use Beffroi\Bundle\Http\Account\ConsentsSection;
use Beffroi\Bundle\Http\Account\TwoFactorSection;
use Beffroi\Bundle\Http\AuthorizationRequestReader;
use Beffroi\Bundle\Http\Decision\ConsentRequiredRenderer;
use Beffroi\Bundle\Http\Decision\DecisionRenderers;
use Beffroi\Bundle\Http\Decision\GrantedRenderer;
use Beffroi\Bundle\Http\Decision\InteractionPage;
use Beffroi\Bundle\Http\Decision\LoginRequiredRenderer;
use Beffroi\Bundle\Http\FapiInteractionId;
use Beffroi\Bundle\Http\FormTarget;
use Beffroi\Bundle\Http\ImageSource;
use Beffroi\Bundle\Http\FormToken;
use Beffroi\Bundle\Http\DeviceApprovalPage;
use Beffroi\Bundle\Http\RecentLogin;
use Beffroi\Bundle\Http\LoginTarget;
use Beffroi\Bundle\Http\AuthorizationRequestReaderInterface;
use Beffroi\Bundle\Http\AuthorizationResponder;
use Beffroi\Bundle\Http\AuthorizationResponderInterface;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\CrossSitePost;
use Beffroi\Bundle\Http\CrossSiteSessionCookie;
use Beffroi\Bundle\Http\BrowserPreferences;
use Beffroi\Bundle\Http\ApplicationPage;
use Beffroi\Bundle\Http\InteractionLocale;
use Beffroi\Bundle\Http\SessionsPage;
use Beffroi\Bundle\Http\ActsPage;
use Beffroi\Bundle\Locale\KnownLocales;
use Beffroi\Bundle\Locale\LocalePreference;
use Beffroi\Bundle\Locale\ServedLocales;
use Beffroi\Bundle\Locale\UserLocale;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\ClientNotificationSender;
use Beffroi\Bundle\Http\PendingApprovalsPage;
use Beffroi\Bundle\Http\LogoutTokenSender;
use Beffroi\Bundle\Http\PasskeyOptionsStore;
use Beffroi\Bundle\Http\ClaimChangesPage;
use Beffroi\Bundle\Http\ProfilePage;
use Beffroi\Bundle\Http\PasskeysPage;
use Beffroi\Bundle\Http\PasswordPage;
use Beffroi\Bundle\Http\ConsentsPage;
use Beffroi\Bundle\Http\PendingLoginStore;
use Beffroi\Bundle\Http\QrCode;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\ResponseMode\AuthorizationResponseRenderers;
use Beffroi\Bundle\Http\ResponseMode\FormPostResponseRenderer;
use Beffroi\Bundle\Http\ResponseMode\QueryResponseRenderer;
use Beffroi\Bundle\Http\ResponseMode\SignedFormPostResponseRenderer;
use Beffroi\Bundle\Http\ResponseMode\SignedQueryResponseRenderer;
use Beffroi\Bundle\Http\Tls\ClientCertificateResolverInterface;
use Beffroi\Bundle\Http\Tls\EdgeClientCertificateResolver;
use Beffroi\Bundle\Http\Tls\PresentedClientCertificate;
use Beffroi\Bundle\Http\TotpProvisioningSealer;
use Beffroi\Bundle\Http\TotpProvisioningStore;
use Beffroi\Bundle\Http\TwoFactorPage;
use Beffroi\Bundle\Key\FilePairwiseSalt;
use Beffroi\Bundle\Key\DormantKeyAlgorithms;
use Beffroi\Bundle\Key\FileTenantKeyRepository;
use Beffroi\Bundle\Key\KmsUnavailableListener;
use Beffroi\Bundle\Load\LoadBudget;
use Beffroi\Bundle\Load\LoadRefusal;
use Beffroi\Bundle\Load\LoadRefusalListener;
use Beffroi\Bundle\Load\OriginLoadListener;
use Beffroi\Bundle\Load\RateLimitedClientLoad;
use Beffroi\Bundle\MessageHandler\TellUserOfPendingApprovalHandler;
use Beffroi\Bundle\MessageHandler\QueueLogoutTokenHandler;
use Beffroi\Bundle\Messenger\EventBusDispatcher;
use Beffroi\Bundle\Messenger\LogoutTokenGivenUpListener;
use Beffroi\Bundle\Messenger\MessengerContract;
use Beffroi\Bundle\Messenger\NotificationRetryPolicy;
use Beffroi\Bundle\Messenger\SealedBodySerializer;
use Beffroi\Bundle\Plane\Plane;
use Beffroi\Bundle\Plane\PlaneRequestListener;
use Beffroi\Bundle\Routing\RouterEndpointLocator;
use Beffroi\Bundle\Scheduler\BeffroiSchedule;
use Beffroi\Bundle\Security\BreachedPasswordListener;
use Beffroi\Bundle\Security\CorePasswordHasher;
use Beffroi\Bundle\Security\IdentityUserProvider;
use Beffroi\Bundle\Security\InteractionLoginHandler;
use Beffroi\Bundle\Security\LoginFailureListener;
use Beffroi\Bundle\Security\LoginSuccessListener;
use Beffroi\Bundle\Security\PasskeyLogin;
use Beffroi\Bundle\Security\PasskeyLoginAuthenticator;
use Beffroi\Bundle\Security\UpstreamAssertionAuthenticator;
use Beffroi\Bundle\Security\PasswordLoginAuthenticator;
use Beffroi\Bundle\Security\PassportProofs;
use Beffroi\Bundle\Security\PwnedPasswords;
use Beffroi\Bundle\Security\PasswordLogin;
use Beffroi\Bundle\Security\RateLimitedAttempts;
use Beffroi\Bundle\Security\SecondFactorGate;
use Beffroi\Bundle\Security\TotpLogin;
use Beffroi\Bundle\Security\TotpLoginAuthenticator;
use Beffroi\Bundle\Security\UserChecker;
use Beffroi\Bundle\Tenant\TenantFactory;
use Beffroi\Bundle\Locale\UserTimeZone;
use Beffroi\Bundle\Doctrine\Repository\DoctrineJournal;
use Beffroi\Bundle\Identity\LocaleClaimFactory;
use Beffroi\Bundle\Identity\WiredClaims;
use Beffroi\Core\Application\Identity\LanguageRecording;
use Beffroi\Core\Application\Identity\SelfDescription;
use Beffroi\Core\Domain\Identity\Claim\Name;
use Beffroi\Core\Domain\Identity\Claim\GivenName;
use Beffroi\Core\Domain\Identity\Claim\FamilyName;
use Beffroi\Core\Domain\Identity\Claim\MiddleName;
use Beffroi\Core\Domain\Identity\Claim\Nickname;
use Beffroi\Core\Domain\Identity\Claim\PreferredUsername;
use Beffroi\Core\Domain\Identity\Claim\Birthdate;
use Beffroi\Core\Domain\Identity\Claim\Gender;
use Beffroi\Core\Domain\Identity\Claim\Locale;
use Beffroi\Core\Domain\Identity\Claim\Zoneinfo;
use Beffroi\Core\Domain\Identity\Claim\ProfileUrl;
use Beffroi\Core\Domain\Identity\Claim\PictureUrl;
use Beffroi\Core\Domain\Identity\Claim\WebsiteUrl;
use Beffroi\Core\Domain\Identity\Claim\PhoneNumber;
use Beffroi\Core\Application\Journal\ActRecording;
use Beffroi\Core\Application\Session\ProvenancePlace;
use Beffroi\Core\Application\Session\SessionProvenanceEnrichment;
use Beffroi\Core\Application\Journal\JournalRetention;
use Beffroi\Bundle\Doctrine\Repository\DoctrineDisclosures;
use Beffroi\Oidc\Application\Archive\DisclosuresChapter;
use Beffroi\Oidc\Application\Disclosure\DisclosureRecording;
use Beffroi\Oidc\Application\Disclosure\DisclosureRetention;
use Beffroi\Oidc\Port\DisclosuresInterface;
use Beffroi\Oidc\Port\DisclosuresOfAPersonInterface;
use Beffroi\Core\Application\Record\DeadRecordRemoval;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use Beffroi\Core\Port\CanPageActiveSessionsInterface;
use Beffroi\Core\Port\CanPageActiveSubscriptionsInterface;
use Beffroi\Core\Port\CanPageActsOfAPersonInterface;
use Beffroi\Core\Port\CanPageChangesOfAPersonInterface;
use Beffroi\Core\Port\CanPageCredentialsInterface;
use Beffroi\Bundle\Doctrine\Repository\DoctrineClaimHistory;
use Beffroi\Core\Application\Archive\Chapter\ChangesChapter;
use Beffroi\Core\Application\Identity\ClaimHistoryRetention;
use Beffroi\Core\Port\AmbientTenantInterface;
use Beffroi\Core\Port\ChangesOfAPersonInterface;
use Beffroi\Core\Port\ClaimHistoryInterface;
use Beffroi\Core\Port\JournalInterface;
use Beffroi\Bundle\Twig\LocaleExtension;
use Beffroi\Bundle\Twig\MomentExtension;
use Beffroi\Bundle\Twig\DeviceExtension;
use Beffroi\Bundle\Twig\PlaceExtension;
use Beffroi\Bundle\Twig\TenantExtension;
use Beffroi\Bundle\Webauthn\FileMetadataBlobStore;
use Beffroi\Core\Application\Authentication\DecoyHash;
use Beffroi\Core\Application\Authentication\AuthenticationRefusal;
use Beffroi\Core\Application\Authentication\LoginCompletion;
use Beffroi\Core\Application\Authentication\PasswordAuthenticator;
use Beffroi\Core\Application\Authentication\PasswordVerification;
use Beffroi\Core\Application\Authentication\PendingLoginVerification;
use Beffroi\Core\Application\Authentication\SecondFactorRequirement;
use Beffroi\Core\Application\Authentication\SessionOpener;
use Beffroi\Core\Application\Authentication\OtherSessionsTermination;
use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Credential\BreachedPasswordLookup;
use Beffroi\Core\Application\Credential\BreachedPasswordRefusal;
use Beffroi\Core\Application\Credential\PasswordChange;
use Beffroi\Core\Application\Credential\CredentialRenaming;
use Beffroi\Core\Application\Credential\CredentialRevocation;
use Beffroi\Core\Application\Group\GroupProvisioner;
use Beffroi\Core\Application\Group\UpstreamMemberships;
use Beffroi\Core\Application\Identity\IdentityLinker;
use Beffroi\Core\Application\Identity\JustInTimeProvisioning;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Application\Key\KeyRetirement;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Application\Key\KeySuccession;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Application\Key\NamedKey;
use Beffroi\Core\Application\Key\RetirementWindow;
use Beffroi\Core\Application\Passkey\PasskeyAuthentication;
use Beffroi\Core\Application\Passkey\PasskeyEnrolment;
use Beffroi\Core\Application\Totp\ActiveTotp;
use Beffroi\Core\Application\Totp\TotpAuthentication;
use Beffroi\Core\Application\Totp\TotpCodeMatcher;
use Beffroi\Core\Application\Totp\BackupCodeSet;
use Beffroi\Core\Application\Totp\BackupCodesRenewal;
use Beffroi\Core\Application\Totp\TotpEnrolment;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\A256Gcm;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\MessageSeal;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\EcdhEsA256Kw;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\EdDsa;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\Es256;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\Ps256;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\Rs256;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\RsaOaep256;
use Beffroi\Core\Bridge\JwtLibrary\JoseContentEncryptionAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseEncryptionAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyFamily;
use Beffroi\Bundle\Saml\JoseSamlEncryptionAlgorithms;
use Beffroi\Bundle\Saml\JoseSamlSigningAlgorithms;
use Beffroi\Bundle\Saml\MappedClaimsWarmer;
use Beffroi\Bundle\Saml\ProviderServedClaims;
use Beffroi\Bundle\Saml\SamlPostPage;
use Beffroi\Bundle\Saml\SignOnAnswers;
use Beffroi\Bundle\Saml\TenantPersistentIdentifierSalt;
use Beffroi\Bundle\Saml\WaitingSignOns;
use Beffroi\Core\Port\KeptDecryptionKeyProviderInterface;
use Beffroi\Core\Port\KeptSigningKeyProviderInterface;
use Beffroi\Saml\Application\SingleSignOn\AttributeRelease;
use Beffroi\Saml\Application\SingleSignOn\SingleSignOn;
use Beffroi\Saml\Bridge\Model\ModelAuthnRequestReceiver;
use Beffroi\Saml\Bridge\Model\DeclaredServiceProviderReader;
use Beffroi\Saml\Bridge\Model\ModelAuthnRequestSender;
use Beffroi\Saml\Port\AuthnRequestSenderInterface;
use Beffroi\Bundle\Saml\UpstreamLoginRequirement;
use Beffroi\Bundle\Saml\UpstreamSignOnAnswer;
use Beffroi\Bundle\Saml\UpstreamSignOnReferences;
use Beffroi\Bundle\Saml\UpstreamSignOns;
use Beffroi\Saml\Bridge\Model\ModelLogoutMessageReceiver;
use Beffroi\Saml\Bridge\Model\ModelSignOutNotifier;
use Beffroi\Saml\Bridge\Model\ModelSignOutResponder;
use Beffroi\Saml\Bridge\Model\TenantSigning;
use Beffroi\Saml\Bridge\Model\UpstreamDecryptionKeys;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;
use Beffroi\Saml\Application\SingleLogout\ProviderLogout;
use Beffroi\Saml\Application\SingleLogout\SessionParticipants;
use Beffroi\Saml\Application\SingleLogout\SingleLogout;
use Beffroi\Saml\Port\ReplayStoreInterface;
use Beffroi\Saml\Port\LogoutChainRepositoryInterface;
use Beffroi\Saml\Port\LogoutMessageReceiverInterface;
use Beffroi\Saml\Port\SignOutNotifierInterface;
use Beffroi\Saml\Port\SessionParticipationRepositoryInterface;
use Beffroi\Saml\Port\SignOutResponderInterface;
use Beffroi\Bundle\Doctrine\Repository\DoctrineReplayStore;
use Beffroi\Bundle\Doctrine\Repository\DoctrineSessionParticipationRepository;
use Beffroi\Saml\Bridge\Model\ModelSignOnResponder;
use Beffroi\Saml\Port\AuthnRequestReceiverInterface;
use Beffroi\Saml\Port\PersistentIdentifierSaltInterface;
use Beffroi\Saml\Port\SignOnResponderInterface;
use Beffroi\Bundle\Saml\RouterIdentityProviderEndpoints;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Saml\LogoutChainCookie;
use Beffroi\Bundle\Saml\LogoutChainPages;
use Beffroi\Bundle\Doctrine\Repository\DoctrineLogoutChainRepository;
use Beffroi\Saml\Application\Metadata\EncryptionCertificates;
use Beffroi\Saml\Application\Metadata\SigningCertificates;
use Beffroi\Saml\Bridge\Model\ModelMetadataWriter;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataWriter;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Port\CertificateIssuerInterface;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml\Port\MetadataWriterInterface;
use Beffroi\Saml\Port\ServiceProviderMetadataWriterInterface;
use Beffroi\Bundle\Doctrine\Repository\DoctrineAcceptedMetadataRepository;
use Beffroi\Bundle\Saml\MetadataFetcher;
use Beffroi\Saml\Application\Metadata\MetadataRefresh;
use Beffroi\Saml\Application\ServiceProvider\ServiceProviderRole;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Bundle\Command\SamlServiceProviderRefreshCommand;
use Beffroi\Bundle\Command\SamlServiceProviderForgetCommand;
use Beffroi\Bundle\MessageHandler\RefreshTheSamlMetadataHandler;
use Beffroi\Bundle\Command\SamlIdentityProviderRefreshCommand;
use Beffroi\Bundle\Command\SamlIdentityProviderForgetCommand;
use Beffroi\Bundle\Saml\WiredProfileClaims;
use Beffroi\Saml\Application\Upstream\UpstreamIdentityProviderRole;
use Beffroi\Saml\Bridge\Configuration\ConfigurationUpstreamIdentityProviders;
use Beffroi\Saml\Bridge\Model\ModelUpstreamMetadataReader;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Port\ProfileClaimsInterface;
use Beffroi\Saml\Port\UpstreamIdentityProvidersInterface;
use Beffroi\Saml\Port\UpstreamMetadataReaderInterface;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\CanForgetAcceptedMetadataInterface;
use Beffroi\Saml\Application\Metadata\AcceptedMetadataForgetting;
use Beffroi\Saml\Port\MetadataFetcherInterface;
use Beffroi\Saml\Port\ServiceProviderMetadataReaderInterface;
use Beffroi\Saml\Port\ServedClaimsInterface;
use Beffroi\Saml\Port\ServiceProvidersInterface;
use Beffroi\Core\Bridge\JwtLibrary\JoseKeyEncryptionAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseMessageSealingAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJweDecrypter;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsSigner;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodyOpener;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodySealer;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use Beffroi\Bundle\Geo\GeoLite2Databases;
use Beffroi\Bundle\Geo\GeoLite2GeoLocator;
use Beffroi\Bundle\Geo\GeoLite2Refresh;
use Beffroi\Core\Bridge\Null\NullUserAgentParser;
use Beffroi\Core\Bridge\Otphp\OtphpTotpAlgorithm;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2i;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha512;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Password\PasswordHasherRegistry;
use Beffroi\Core\Bridge\Password\WiredPasswordAlgorithms;
use Beffroi\Core\Bridge\Session\WiredAuthenticationPredicates;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Domain\Session\PhishingResistantHardware;
use Beffroi\Core\Domain\Session\SingleFactor;
use Beffroi\Core\Domain\Session\TwoFactors;
use Beffroi\Core\Bridge\Webauthn\MetadataBlobVerifier;
use Beffroi\Core\Bridge\Webauthn\StoredMetadata;
use Beffroi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Beffroi\Core\Bridge\Webauthn\WebauthnPasskeyAuthenticator;
use Beffroi\Core\Bridge\Webauthn\WebauthnPasskeyRegistrar;
use Beffroi\Core\Domain\Record\WhatATokenStillNeeds;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\CodeAttemptLimiterInterface;
use Beffroi\Core\Port\ContentEncryptionAlgorithmsInterface;
use Beffroi\Core\Port\BreachedPasswordsInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\DecryptionKeyProviderInterface;
use Beffroi\Core\Port\GeoLocatorInterface;
use Beffroi\Core\Port\JweDecrypterInterface;
use Beffroi\Core\Port\JwsSignerInterface;
use Beffroi\Core\Port\JwsVerifierInterface;
use Beffroi\Core\Port\KeyAlgorithmsInterface;
use Beffroi\Core\Port\RotationSchedulesInterface;
use Beffroi\Core\Port\KeyEncryptionAlgorithmsInterface;
use Beffroi\Core\Port\KeyPairGeneratorInterface;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Port\MessageBodyOpenerInterface;
use Beffroi\Core\Port\MessageBodySealerInterface;
use Beffroi\Core\Port\MessageKeyProviderInterface;
use Beffroi\Core\Port\MessageSealingAlgorithmsInterface;
use Beffroi\Core\Port\MetadataBlobStoreInterface;
use Beffroi\Core\Port\PasskeyAuthenticatorInterface;
use Beffroi\Core\Port\PasskeyRegistrarInterface;
use Beffroi\Core\Port\PasswordAttemptLimiterInterface;
use Beffroi\Core\Port\AuthenticationPredicatesInterface;
use Beffroi\Core\Port\PasswordAlgorithmsInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Core\Port\PublicKeySetProviderInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Core\Port\SigningKeyProviderInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Port\UserAgentParserInterface;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use Beffroi\Core\Port\AtomicWritesInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Application\Authorization\AuthenticationRequirement;
use Beffroi\Oidc\Application\Authorization\AuthorizationCodeIssuer;
use Beffroi\Oidc\Application\Authorization\AuthorizationHandler;
use Beffroi\Oidc\Application\Authorization\AuthorizationRequestParser;
use Beffroi\Oidc\Application\Authorization\CodeChallengeMethods;
use Beffroi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Beffroi\Oidc\Application\Authorization\RequestObjectReader;
use Beffroi\Oidc\Application\Authorization\RequestObjectResolver;
use Beffroi\Oidc\Application\Authorization\RequestObjectValidator;
use Beffroi\Oidc\Application\Authorization\ResponseDocumentIssuer;
use Beffroi\Oidc\Application\Claims\AssignedSubjectIdentifiers;
use Beffroi\Oidc\Application\Claims\PairwiseSubjectIdentifierResolver;
use Beffroi\Oidc\Application\Claims\Sector\JwksUriSectorIdentifier;
use Beffroi\Oidc\Application\Claims\Sector\RedirectUriSectorIdentifier;
use Beffroi\Oidc\Application\Claims\Sector\RegisteredSectorIdentifier;
use Beffroi\Oidc\Application\Claims\SectorIdentifiers;
use Beffroi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Beffroi\Oidc\Application\Claims\ServedClaims;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Application\Client\AcceptedAssertionAudiences;
use Beffroi\Oidc\Application\Client\ClientIdentifierDrawer;
use Beffroi\Oidc\Application\Client\ClientMetadataReader;
use Beffroi\Oidc\Application\Client\ClientAssertionValidator;
use Beffroi\Oidc\Application\Client\RegisteredClients;
use Beffroi\Oidc\Application\Client\ClientAuthenticationMethods;
use Beffroi\Oidc\Application\Client\ClientAuthenticationRequestParser;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\Client\ClientDocumentIssuer;
use Beffroi\Oidc\Application\Client\ClientKeySetProvider;
use Beffroi\Oidc\Application\Key\PublishedKeySetProvider;
use Beffroi\Oidc\Application\Client\Method\ClientSecretBasic;
use Beffroi\Oidc\Application\Client\Method\ClientSecretJwt;
use Beffroi\Oidc\Application\Client\Method\ClientSecretPost;
use Beffroi\Oidc\Application\Client\Method\NoAuthentication;
use Beffroi\Oidc\Application\Client\Method\PrivateKeyJwt;
use Beffroi\Oidc\Application\Client\Method\SelfSignedTlsClientAuth;
use Beffroi\Oidc\Application\Client\Method\TlsClientAuth;
use Beffroi\Oidc\Application\Discovery\DiscoveryHandler;
use Beffroi\Oidc\Application\Discovery\Metadata\ProviderIdentity;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedClientRegistration;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedScopes;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedResponses;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedGrants;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedBackchannelAuthentication;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedDeviceAuthorization;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedAuthenticationContext;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedIdToken;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedUserInfo;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedClientAuthentication;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedClaims;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedRequestObjects;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedPkce;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedRevocation;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedPushedAuthorization;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedIntrospection;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedIssuerParameter;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedLogout;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedMutualTls;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedDpop;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedSignedAuthorizationResponse;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedMutualTlsEndpoints;
use Beffroi\Oidc\Application\AuthorizationDetails\ServedAuthorizationDetailTypes;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedAuthorizationDetails;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedProtectedResources;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Discovery\JwksHandler;
use Beffroi\Oidc\Application\Dpop\DpopProofValidator;
use Beffroi\Oidc\Application\Dpop\DpopProofVerifier;
use Beffroi\Oidc\Application\EndSession\BackChannelLogout;
use Beffroi\Oidc\Application\EndSession\EndSessionHandler;
use Beffroi\Oidc\Application\EndSession\SessionTokensRevocation;
use Beffroi\Oidc\Application\EndSession\EndSessionRequestParser;
use Beffroi\Oidc\Application\EndSession\FrontChannelLogout;
use Beffroi\Oidc\Application\EndSession\LogoutTokenIssuer;
use Beffroi\Oidc\Application\Interaction\ThirdPartyInitiatedLoginHandler;
use Beffroi\Oidc\Application\Introspection\IntrospectionHandler;
use Beffroi\Oidc\Application\Key\AccessTokenJwsKind;
use Beffroi\Oidc\Application\Key\IdTokenJwsKind;
use Beffroi\Oidc\Application\Key\LogoutTokenJwsKind;
use Beffroi\Oidc\Application\Key\PushedRequestJweKind;
use Beffroi\Oidc\Application\Key\RequestObjectJweKind;
use Beffroi\Oidc\Application\Key\ResponseDocumentJwsKind;
use Beffroi\Oidc\Application\PushedAuthorization\PushedAuthorizationHandler;
use Beffroi\Oidc\Application\Consent\ConsentGranting;
use Beffroi\Oidc\Application\Consent\RequiredConsent;
use Beffroi\Oidc\Application\Consent\ConsentRevocation;
use Beffroi\Oidc\Application\Exchange\PresentedAccessTokenType;
use Beffroi\Oidc\Application\Exchange\PresentedTokenTypes;
use Beffroi\Oidc\Application\Grant\RecordedGrants;
use Beffroi\Oidc\Application\Trust\IssuerAssertionValidator;
use Beffroi\Oidc\Application\Ciba\ApprovalAuthenticationRequirement;
use Beffroi\Oidc\Application\Ciba\BackchannelApproval;
use Beffroi\Oidc\Application\Ciba\BackchannelAuthenticationHandler;
use Beffroi\Oidc\Application\Ciba\Hint\IdTokenUserHint;
use Beffroi\Oidc\Application\Hint\LoginHints;
use Beffroi\Oidc\Application\Hint\SubjectLoginHint;
use Beffroi\Oidc\Application\Hint\UsernameLoginHint;
use Beffroi\Oidc\Application\Ciba\ServedDeliveryModes;
use Beffroi\Oidc\Application\Ciba\SignedBackchannelRequest;
use Beffroi\Oidc\Application\Ciba\UserHints;
use Beffroi\Oidc\Application\Device\DeviceApproval;
use Beffroi\Oidc\Application\Device\DeviceAuthorizationHandler;
use Beffroi\Oidc\Application\PushedAuthorization\PushedAuthorizationRequestResolver;
use Beffroi\Oidc\Application\Revocation\RevocationHandler;
use Beffroi\Oidc\Application\Token\AccessTokenInspector;
use Beffroi\Oidc\Application\Token\PersonOfAnAccessToken;
use Beffroi\Oidc\Application\Token\AccessTokenVerifier;
use Beffroi\Oidc\Application\Token\AuthorizationCodeGrant;
use Beffroi\Oidc\Application\Token\ClientCredentialsGrant;
use Beffroi\Oidc\Application\Token\JwtBearerGrant;
use Beffroi\Oidc\Application\Token\TokenExchangeGrant;
use Beffroi\Oidc\Application\Token\BackchannelAuthenticationGrant;
use Beffroi\Oidc\Application\Token\DeviceCodeGrant;
use Beffroi\Oidc\Application\Token\RefreshTokenDue;
use Beffroi\Oidc\Application\Token\RequestedAuthorizationDetails;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\Confirmations;
use Beffroi\Oidc\Application\Token\JwtAccessTokenVerifier;
use Beffroi\Oidc\Application\Token\JwtIdTokenIssuer;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenVerifier;
use Beffroi\Oidc\Application\Token\PresentedAccessTokenParser;
use Beffroi\Oidc\Application\Token\RefreshTokenGrant;
use Beffroi\Oidc\Application\Token\SealedPerson;
use Beffroi\Oidc\Application\Token\ServedAccessTokenShapes;
use Beffroi\Oidc\Application\Token\ServedGrants;
use Beffroi\Oidc\Application\Flow\TheClientActsForItself;
use Beffroi\Oidc\Application\Flow\TheClientAsksForATokenAlone;
use Beffroi\Oidc\Application\Flow\TheProviderIsAskedWhoTheUserIs;
use Beffroi\Oidc\Application\Flow\TheRefreshTokenIsSpent;
use Beffroi\Oidc\Application\Flow\TheResourceServerAsksWhatTheTokenIs;
use Beffroi\Oidc\Application\Flow\TheTokenIsGivenBack;
use Beffroi\Oidc\Application\Flow\TheUserIsAskedOnAnotherDevice;
use Beffroi\Oidc\Application\Flow\TheUserIsAskedThroughABackchannel;
use Beffroi\Oidc\Application\Flow\TheUserIsSentToTheClient;
use Beffroi\Oidc\Application\Flow\WiredFlowPictures;
use Beffroi\Oidc\Port\FlowPicturesInterface;
use Beffroi\Oidc\Application\Token\RefreshTokenRevocation;
use Beffroi\Oidc\Application\Token\TokenHandler;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Application\UserInfo\UserInfoHandler;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationTrustedIssuers;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryClientAssertionSecretVerifier;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryJweEncrypter;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryProofKeyVerifier;
use Beffroi\Oidc\Bridge\Null\NoDpopNonce;
use Beffroi\Oidc\Bridge\Pki\PkiFrameworkCertificateReader;
use Beffroi\Oidc\Port\AccessTokenIssuerInterface;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use Beffroi\Oidc\Port\CanPageActiveConsentsInterface;
use Beffroi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Beffroi\Oidc\Port\CanRevokeGrantsByConsentInterface;
use Beffroi\Oidc\Port\RecordedGrantsInterface;
use Beffroi\Oidc\Port\CertificateReaderInterface;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use Beffroi\Oidc\Port\ClientAssertionReplayGuardInterface;
use Beffroi\Oidc\Port\IssuerAssertionReplayGuardInterface;
use Beffroi\Oidc\Port\SoftwareStatementReplayGuardInterface;
use Beffroi\Oidc\Port\PresentedTokenTypesInterface;
use Beffroi\Oidc\Port\TrustedIssuersInterface;
use Beffroi\Oidc\Port\RequestObjectReplayGuardInterface;
use Beffroi\Oidc\Port\ClientAssertionSecretVerifierInterface;
use Beffroi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;
use Beffroi\Oidc\Port\ClientJwksFetcherInterface;
use Beffroi\Oidc\Domain\Token\CertificateConfirmationKind;
use Beffroi\Oidc\Domain\Token\KeyConfirmationKind;
use Beffroi\Oidc\Port\ClientLoadBudgetInterface;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\AuthorizationDetailsReaderInterface;
use Beffroi\Oidc\Port\ConfirmationReaderInterface;
use Beffroi\Oidc\Port\ServedTokenSchemesInterface;
use Beffroi\Oidc\Port\RegisteredResourcesInterface;
use Beffroi\Oidc\Port\ClientStoreInterface;
use Beffroi\Oidc\Application\Client\Registration\ClientConfigurationAccess;
use Beffroi\Oidc\Application\Client\Registration\ClientUseRecording;
use Beffroi\Oidc\Application\Client\ClientInventory;
use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenIssuance;
use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenRevocation;
use Beffroi\Oidc\Application\Client\Registration\RegisteredClientRemoval;
use Beffroi\Oidc\Application\Client\Registration\UnusedClientRemoval;
use Beffroi\Oidc\Application\Client\Registration\ClientConfigurationReader;
use Beffroi\Oidc\Application\Client\Registration\ClientConfigurationRemoval;
use Beffroi\Oidc\Application\Client\Registration\ClientConfigurationReplacement;
use Beffroi\Oidc\Application\Client\Registration\ClientRegistrationHandler;
use Beffroi\Oidc\Application\Client\Registration\RegistrationUnderThePolicy;
use Beffroi\Oidc\Port\ClientConfigurationEndpointInterface;
use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenAuthorization;
use Beffroi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Beffroi\Oidc\Application\Client\Registration\SoftwareStatementAuthorization;
use Beffroi\Oidc\Application\Client\Registration\SoftwareStatementVerifier;
use Beffroi\Oidc\Application\Client\Registration\RegistrationAuthorizations;
use Beffroi\Oidc\Application\Client\Registration\RegistrationHeldToItsSector;
use Beffroi\Oidc\Application\Client\Registration\RegistrationHeldToTheTenant;
use Beffroi\Oidc\Application\Scope\OfferedScopes;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRegistrationPolicy;
use Beffroi\Oidc\Port\ClientRegistrationPolicyInterface;
use Beffroi\Oidc\Port\ClientInventoryInterface;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\IssuedInitialAccessTokensInterface;
use Beffroi\Oidc\Port\OfferedScopesInterface;
use Beffroi\Oidc\Port\RegisteredScopesInterface;
use Beffroi\Oidc\Port\RegisteredAccessTokenShapesInterface;
use Beffroi\Oidc\Port\ServedAccessTokenShapesInterface;
use Beffroi\Oidc\Port\ServedAuthorizationDetailTypesInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Beffroi\Oidc\Port\CompactJwtReaderInterface;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensByConsentInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use Beffroi\Oidc\Port\RefreshTokensOfAConsentInterface;
use Beffroi\Oidc\Port\DpopProofReplayGuardInterface;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\IdTokenIssuerInterface;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use Beffroi\Oidc\Port\JweEncrypterInterface;
use Beffroi\Oidc\Port\JwtKeyVerifierInterface;
use Beffroi\Oidc\Port\LoggedInClientsInterface;
use Beffroi\Oidc\Port\MutualTlsEndpointLocatorInterface;
use Beffroi\Oidc\Port\ProofKeyVerifierInterface;
use Beffroi\Oidc\Port\ProvableMethodsInterface;
use Beffroi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Ciba\PingDelivery;
use Beffroi\Oidc\Domain\Ciba\PollDelivery;
use Beffroi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Beffroi\Oidc\Port\PendingApprovalNotifierInterface;
use Beffroi\Oidc\Port\ServedDeliveryModesInterface;
use Beffroi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
use Beffroi\Oidc\Port\PushedAuthorizationRequirementInterface;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Beffroi\Oidc\Port\RequestObjectFetcherInterface;
use Beffroi\Oidc\Port\LogoutTokenDeliveryInterface;
use Beffroi\Oidc\Port\ServedLogoutChannelsInterface;
use Beffroi\Oidc\Port\ServedResponseModesInterface;
use Beffroi\Oidc\Port\AssignedSubjectTypesInterface;
use Beffroi\Oidc\Port\PairwiseSaltInterface;
use Beffroi\Oidc\Port\PairwiseSubjectRepositoryInterface;
use Beffroi\Oidc\Port\PresentedSubjectReaderInterface;
use Beffroi\Oidc\Port\SectorIdentifierDocumentFetcherInterface;
use Beffroi\Oidc\Port\SectorIdentifiersInterface;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;
use Beffroi\Oidc\Port\UnsignedRequestObjectsInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\HS256;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\RateLimiter\Storage\CacheStorage;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_locator;
use Webauthn\MetadataService\CertificateChain\CertificateChainValidator;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\StatusReportRepository;
use Beffroi\Core\Port\PushSubscriptionRepositoryInterface;
use Beffroi\Core\Port\ApplicationServerKeyProviderInterface;
use Beffroi\Core\Port\ApplicationServerAlgorithmsInterface;
use Beffroi\Core\Bridge\JwtLibrary\JoseApplicationServerAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\Algorithm\Vapid;
use Beffroi\Core\Application\Push\PushSubscriptionNaming;
use Beffroi\Core\Application\Push\PushSubscriptionRevocation;
use Beffroi\Core\Application\Push\PushSubscriptionEnrolment;
use Beffroi\Bundle\Configuration\PasswordsSection;
use Beffroi\Bundle\Configuration\WebPushSection;
use Beffroi\Bundle\Push\WebPushSender;
use Beffroi\Bundle\Http\NotificationsPage;
use Beffroi\Bundle\Http\BundleScript;
use Beffroi\Bundle\Http\Account\NotificationsSection;
use Beffroi\Bundle\Http\Account\SessionsSection;
use Beffroi\Bundle\Http\Account\PasswordSection;
use Beffroi\Bundle\Http\Account\ActsSection;
use Beffroi\Bundle\Doctrine\Repository\DoctrinePushSubscriptionRepository;
use Beffroi\Bundle\Ciba\WebPushApprovalChannel;

/*
 * Every service of the core, of the module and of the bundle, autowired, the ports aliased to their one
 * implementation (architecture §3.4, §4.11, §5.2 to §5.4).
 */
return static function (ContainerConfigurator $container): void {
    $services = $container->services();
    $services
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->private()
        // the core announces in PSR-14; what listens is the event bus, never the dispatcher of the kernel
        ->bind(EventDispatcherInterface::class, service(EventBusDispatcher::class));

    // The bundle
    $services->set(EventBusDispatcher::class)->args([service('event.bus')]);
    $services->set(PlaneRequestListener::class)->args(['%env(enum:' . Plane::class . ':BEFFROI_PLANE)%']);
    $services->set(TenantFactory::class);

    // The bundle: the two planes (architecture §5.2)
    $services->load('Beffroi\\Bundle\\Controller\\', '../src/Controller/');
    $services->set(RequestContextFactory::class);
    // what every answer of a protected resource of the provider names the exchange with (FAPI 1.0
    // Advanced Final §6.2.1): read where the resource that will answer is known, written where the
    // answer is written, and asked of no endpoint
    $services->set(FapiInteractionId::class);
    $services->set(BrowserSession::class);
    $services->set(InteractionPages::class);
    // what a browser posted from another site without the session cookie, posted again from this provider's own
    // origin, which the cookie accompanies (beffroi/saml S-28): asked first by each endpoint a party posts a browser
    // to from another site, the single sign-on and single logout services, the authorization and end session endpoints
    $services->set(CrossSitePost::class);
    // and the cookie of a session started for such a request taken off its answer, on every endpoint of this plane,
    // so that no page of another site replaces the session cookie the browser holds (S-28)
    $services->set(CrossSiteSessionCookie::class);
    // what a page of this plane adds to the policy its answer carries, the deployment writing the rest
    // (PolicyCompletion): the origin of the client the page is answering, named in "form-action", without
    // which a browser refuses the redirection that takes the code there (FormTarget), and the origins of
    // the images the consent page shows, named in "img-src" (ImageSource)
    $services->set(FormTarget::class);
    $services->set(ImageSource::class);
    // which page of a table a request asks for, and the page of the rows a selection finds: the one word
    // and the one number every table of this plane is paged by, and the one place a count and a slice are
    // written (architecture §5.2)
    $services->set(AskedPage::class);
    $services->set(AskedPeriod::class);
    $services->set(PageOfRows::class);
    // what every page of the account asks first: the session of this browser, and the form token when it posts
    // what carries a refusal across the redirection every form of these pages answers with (issue #481)
    $services->set(WhatWasRefused::class);
    $services->set(FormToken::class);
    // where a page of the provider that is not an authorization request sends a browser to sign in, and
    // where the login of the firewall sends it back (RFC 8628 §3.3)
    $services->set(LoginTarget::class);
    // the address an interaction passed at the first step of its login page, when the tenant federates a domain
    // (beffroi/saml S-61)
    $services->set(LoginAddresses::class);
    // and where an address of a federated domain goes from there: the sign-on of its upstream provider (S-51, S-62)
    $services->set(UpstreamDiscovery::class);
    // under a one-time reference the sign-on takes, so that no page of another site starts one (S-51)
    $services->set(UpstreamSignOnReferences::class);
    // what a page of the account that adds or takes away a way in asks of a session before the form: a
    // proof given a short while ago, and the login of the firewall when there is none (issue #552); which
    // pages ask is said by the pages themselves and read where the kernel is about to call one, so the rule
    // reaches the GET and the POST of a page by construction (issue #580)
    $services->set(RecentLogin::class);
    $services->set(RecentProofListener::class);
    $services->set(BreachedPasswordDemand::class);
    $services->set(DeviceApprovalPage::class);
    $services->set(PendingApprovalsPage::class);
    // Reaching a user through the push service of a browser they signed in with (RFC 8030, §5.6): the
    // pages they subscribe on, what leaves this provider, and the channel the lane hands an approval to.
    // The channel and the algorithm of the key are tagged by WebPushSection and only when a deployment
    // names a subject, a channel nobody wired being a channel nobody wanted.
    $services->set(PushSubscriptionEnrolment::class);
    $services->set(PushSubscriptionNaming::class);
    $services->set(PushSubscriptionRevocation::class);
    $services->set(NotificationsPage::class);
    $services->set(WebPushSender::class)->args([
        '$subject' => '',
        '$timeout' => WebPushSection::DEFAULT_TIMEOUT,
    ]);
    $services->set(WebPushApprovalChannel::class);
    $services->set(AccountAccess::class);
    $services->set(BundleScript::class);
    // the pages of the account, in the order they are wired: what the home of the account offers, and the
    // one place a kind of credential is known; a page added to the account is a section beside these and a
    // line here, and neither the home page nor its template is edited
    // first of the sections: every other one says what the account holds, this one says that somebody is
    // waiting on it now, and it is what makes the page of the answers findable at all (BCP 10027 §5.2)
    $services->set(ApprovalsSection::class)->tag('beffroi.account_section');
    $services->set(ProfileSection::class)->tag('beffroi.account_section');
    $services->set(PasskeysSection::class)->tag('beffroi.account_section');
    $services->set(TwoFactorSection::class)->tag('beffroi.account_section');
    $services->set(ConsentsSection::class)->tag('beffroi.account_section');
    // where this person is signed in, and the page that ends one of those sessions (issue #450)
    $services->set(SessionsSection::class)->tag('beffroi.account_section');
    $services->set(SessionsPage::class);
    // what one application holds of a person, behind each line of what they agreed to (issue #451): the
    // reading the page and "beffroi:user:applications" both ask for
    $services->set(ApplicationHoldings::class);
    $services->set(ApplicationPage::class);
    // what the journal holds of the sign-ins of this person, successes and refusals (issue #454): after
    // where they are signed in, because a refusal somebody else caused is read once and a session is read
    // again, and before the browsers the provider can reach
    $services->set(PasswordSection::class)->tag('beffroi.account_section');
    $services->set(ActsSection::class)->tag('beffroi.account_section');
    $services->set(ActsPage::class);
    $services->set(NotificationsSection::class)->tag('beffroi.account_section');
    // everything this provider holds about this person, in one file they ask for (issue #453): last of
    // the sections, because it is the one thing none of the pages above replaces
    $services->set(ArchiveSection::class)->tag('beffroi.account_section');
    $services->set(AccountSections::class)->args([tagged_iterator('beffroi.account_section')]);
    $services->set(AccountHomePage::class);
    // the languages this deployment has, read by the pages of the interaction plane and by whatever
    // writes to a user out of any request of theirs: one list, or a translator is asked for a language
    // that has no catalogue (architecture §5.7)
    $services->set(ServedLocales::class)->args([
        '$enabledLocales' => '%kernel.enabled_locales%',
        '$defaultLocale' => '%kernel.default_locale%',
    ]);
    $services->set(UserLocale::class);
    // what a browser asked the pages to look and read like, on one cookie with a slot per preference
    // (issue #573): the language is one of them, read back against the list above (issue #448), and a
    // preference an application adds is a slot tagged beside it and no second cookie
    $services->set(LocalePreference::class)->tag('beffroi.browser_preference');
    $services->set(BrowserPreferences::class)->args([tagged_iterator('beffroi.browser_preference')]);
    $services->set(LocaleExtension::class);
    // every act of the provider, written down, read and forgotten again (issue #454)
    $services->set(DoctrineJournal::class);
    $services->alias(JournalInterface::class, DoctrineJournal::class);
    $services->alias(ActsOfAPersonInterface::class, DoctrineJournal::class);
    $services->alias(CanPageActsOfAPersonInterface::class, DoctrineJournal::class);
    $services->set(ActRecording::class);
    $services->set(JournalRetention::class);
    // What a client was given of a person, beside the act that gave it (issue #590): the register the
    // journal cannot hold, read by the chapter below and forgotten by the step that forgets the acts, the
    // duration being one duration for the two tables.
    $services->set(DoctrineDisclosures::class);
    $services->alias(DisclosuresInterface::class, DoctrineDisclosures::class);
    $services->alias(DisclosuresOfAPersonInterface::class, DoctrineDisclosures::class);
    $services->set(DisclosureRecording::class);
    $services->set(DisclosureRetention::class);
    // Everything this provider holds about one person, in one file they ask for (RGPD articles 15 and 20,
    // issue #453). The chapters are what the document is assembled from and what the page names: one per
    // kind of fact, tagged, in the order the file holds them, so a table this provider comes to hold about
    // a person is a chapter added here and nothing else edited. One of them is the module's, a consent
    // being what a protocol calls the permission a person gave a client.
    $services->set(DoctrinePersonalArchiveRepository::class);
    $services->alias(PersonalArchiveRepositoryInterface::class, DoctrinePersonalArchiveRepository::class);
    $services->set(DoctrineGroupMembershipRepository::class);
    $services->alias(GroupsOfAPersonInterface::class, DoctrineGroupMembershipRepository::class);
    $services->alias(GroupMembershipRepositoryInterface::class, DoctrineGroupMembershipRepository::class);
    // the groups of the tenant by their name: what the console creates and what the declaration of an
    // upstream provider maps the values it asserts to (issue #782)
    $services->set(DoctrineGroupRepository::class);
    $services->alias(GroupRepositoryInterface::class, DoctrineGroupRepository::class);
    $services->alias(LinkedIdentitiesOfAPersonInterface::class, DoctrineLinkedIdentityRepository::class);
    $services->set(ProfileChapter::class)->tag('beffroi.archive_chapter');
    $services->set(CredentialsChapter::class)->tag('beffroi.archive_chapter');
    $services->set(LinkedIdentitiesChapter::class)->tag('beffroi.archive_chapter');
    $services->set(GroupsChapter::class)->tag('beffroi.archive_chapter');
    $services->set(ConsentsChapter::class)->tag('beffroi.archive_chapter');
    $services->set(SessionsChapter::class)->tag('beffroi.archive_chapter');
    $services->set(JournalChapter::class)->tag('beffroi.archive_chapter');
    $services->set(ChangesChapter::class)->tag('beffroi.archive_chapter');
    $services->set(DisclosuresChapter::class)->tag('beffroi.archive_chapter');
    $services->set(ArchiveAssembly::class)->args([
        '$chapters' => tagged_iterator('beffroi.archive_chapter'),
    ]);
    $services->set(ArchiveRequest::class);
    $services->set(ArchiveDisposal::class);
    $services->set(ArchiveHandout::class);
    $services->set(ArchiveRetention::class);
    // The container a ready file may leave in, under the passphrase of the person who asks (issue #483).
    // A second format is a class here and a line of the page it is read by, which names no format.
    $services->set(ZipArchiveContainer::class);
    $services->alias(ArchiveContainerInterface::class, ZipArchiveContainer::class);
    $services->set(ArchivePage::class)->args([
        '$chapters' => tagged_iterator('beffroi.archive_chapter'),
    ]);
    // What a person may say of themselves (issue #452), in the order a page offers them: a claim is a
    // class tagged here, and the policy of a tenant names the ones its people may say. The phone number
    // is last and is not a claim of the profile: saying it takes back what was verified of the old one.
    $services->set(Name::class)->tag('beffroi.claim');
    $services->set(GivenName::class)->tag('beffroi.claim');
    $services->set(FamilyName::class)->tag('beffroi.claim');
    $services->set(MiddleName::class)->tag('beffroi.claim');
    $services->set(Nickname::class)->tag('beffroi.claim');
    $services->set(PreferredUsername::class)->tag('beffroi.claim');
    $services->set(Birthdate::class)->tag('beffroi.claim');
    $services->set(Gender::class)->tag('beffroi.claim');
    // the language a person reads is a choice of the ones that exist, which only ICU knows (issue #479),
    // and not of the ones this deployment serves: that list answers which language a page is in
    $services->set(KnownLocales::class);
    $services
        ->set(Locale::class)
        ->factory(LocaleClaimFactory::of(...))
        ->args([service(KnownLocales::class)])
        ->tag('beffroi.claim');
    $services->set(Zoneinfo::class)->tag('beffroi.claim');
    $services->set(ProfileUrl::class)->tag('beffroi.claim');
    $services->set(PictureUrl::class)->tag('beffroi.claim');
    $services->set(WebsiteUrl::class)->tag('beffroi.claim');
    $services->set(PhoneNumber::class)->tag('beffroi.claim');
    $services->set(WiredClaims::class)->args([tagged_iterator('beffroi.claim')]);
    $services->set(SelfDescription::class);
    // what a claim of a person used to say, and what they made it say (issue #482): written in the unit of
    // work that changed the record, because a record changed whose history was not is a hole in the one
    // thing a history is for
    $services->set(DoctrineClaimHistory::class);
    $services->alias(ClaimHistoryInterface::class, DoctrineClaimHistory::class);
    $services->alias(ChangesOfAPersonInterface::class, DoctrineClaimHistory::class);
    $services->alias(CanPageChangesOfAPersonInterface::class, DoctrineClaimHistory::class);
    $services->set(ClaimHistoryRetention::class);
    // the language a person chose, written on their account (issue #471)
    $services->set(LanguageRecording::class);
    // the clock a date is read on, and the one filter that writes it (issue #469)
    $services->set(UserTimeZone::class);
    $services->set(MomentExtension::class);
    // where a provenance came from, on the two pages that show one (issue #473)
    $services->set(PlaceExtension::class);
    $services->set(DeviceExtension::class);
    // what the pages read of the organisation the visitor came for (issue #449)
    $services->set(TenantExtension::class);
    $services->set(InteractionLocale::class)->args([
        // the port and not the provider: what it asks is the tenant of this unit of work, and a unit of
        // work that has none has nobody signed in either (issue #485)
        '$tenants' => service(AmbientTenantInterface::class),
    ]);
    // how the answer of the authorization endpoint reaches the client (Multiple Response Type Encoding
    // Practices §2.1): one class per mode, and what is tagged is what the parser accepts and what the
    // discovery document announces, never an enumeration kept beside them
    $services->set(QueryResponseRenderer::class)->tag('beffroi.response_mode');
    $services->set(FormPostResponseRenderer::class)->tag('beffroi.response_mode');
    // JARM §2.1: the same two deliveries, of a document the tenant signs rather than of the parameters
    $services->set(SignedQueryResponseRenderer::class)->tag('beffroi.response_mode');
    $services->set(SignedFormPostResponseRenderer::class)->tag('beffroi.response_mode');
    $services->set(AuthorizationResponseRenderers::class)->args([tagged_iterator('beffroi.response_mode')]);
    $services->alias(ServedResponseModesInterface::class, AuthorizationResponseRenderers::class);

    // One way of answering per decision of the authorization endpoint (architecture §4.3): a decision
    // the provider gains is a renderer beside these and a line here, and nothing reads a class name
    $services->set(InteractionPage::class);
    $services->set(LoginRequiredRenderer::class)->tag('beffroi.authorization_decision');
    $services->set(ConsentRequiredRenderer::class)->tag('beffroi.authorization_decision');
    $services->set(GrantedRenderer::class)->tag('beffroi.authorization_decision');
    $services->set(DecisionRenderers::class)->args([tagged_iterator('beffroi.authorization_decision')]);
    $services->set(AuthorizationResponder::class);
    $services->alias(AuthorizationResponderInterface::class, AuthorizationResponder::class);
    // the two resolvers of the authorization endpoint, in the order the protocol gives them (RFC 9126 §4, RFC 9101 §6.1)
    $services->set(AuthorizationRequestReader::class);
    $services->alias(AuthorizationRequestReaderInterface::class, AuthorizationRequestReader::class);
    $services->set(PasskeyOptionsStore::class);
    $services->set(ProfilePage::class);
    $services->set(ClaimChangesPage::class);
    $services->set(PasskeysPage::class);
    $services->set(PasswordPage::class);
    $services->set(ConsentsPage::class);
    // the second factor: the login held between the password and the code, the provisioning of an enrolment sealed under the KMS of the tenant, the QR code drawn by the bundle
    $services->set(PendingLoginStore::class);
    $services->set(TotpProvisioningSealer::class);
    $services->set(TotpProvisioningStore::class);
    $services->set(QrCode::class);
    $services->set(TwoFactorPage::class);
    $services->set(RouterEndpointLocator::class);
    $services->alias(EndpointLocatorInterface::class, RouterEndpointLocator::class);
    $services->alias(MutualTlsEndpointLocatorInterface::class, RouterEndpointLocator::class);
    // RFC 7592 §3: the URL of one client, which the router knows and nothing else writes down
    $services->alias(ClientConfigurationEndpointInterface::class, RouterEndpointLocator::class);
    // the certificate a client presented at the handshake, read from what the edge proves and never from
    // a header (decision 0006); a deployment behind another proxy replaces this
    // implementation rather than teaching it a header to trust
    $services->set(EdgeClientCertificateResolver::class);
    $services->alias(ClientCertificateResolverInterface::class, EdgeClientCertificateResolver::class);
    $services->set(PresentedClientCertificate::class);

    // The bundle: the console (architecture §5.5)
    $services->load('Beffroi\\Bundle\\Command\\', '../src/Command/');
    // What "beffroi:doctor" looks at: one point is one class tagged here, so a point added is a class
    // added and never a branch of the command (issue #196)
    $services->get(DoctorCommand::class)->args([
        '$checks' => tagged_iterator('beffroi.doctor_check'),
    ]);
    // Whether the transport the notifications are routed to is tried again on the schedule the retirement
    // of a signing key assumes: the two locators of the component say what the container routes a logout
    // token to and what tries each transport again, and the policy is the object the window reads (§4.9)
    $services
        ->set(NotificationsLanePatience::class)
        ->args([
            service('messenger.senders_locator'),
            service('messenger.retry_strategy_locator'),
            service(NotificationRetryPolicy::class),
            service(LogoutTokenDeliveryInterface::class),
        ])
        ->tag('beffroi.doctor_check');

    // The bundle: the endpoints of the FIDO2 server API for the FIDO Conformance Tools (architecture §7); their
    // routes are a file of their own (config/routes/fido-conformance.php) an application imports in development
    // only, and a controller no route names is dropped from the container
    $services->load('Beffroi\\Bundle\\Fido\\Conformance\\', '../src/Fido/Conformance/');
    // The bundle: what answers a backchannel request when the certification suite is the one waiting for
    // the answer (CIBA Core §10.1), on the same terms as the endpoints above and in the same place in a
    // deployment: a file of routes of its own (config/routes/ciba-conformance.php), development only
    $services->load('Beffroi\\Bundle\\Ciba\\Conformance\\', '../src/Ciba/Conformance/');

    // The bundle: the handlers of its own messages and what time does on its own (architecture §5.6)
    $services->load('Beffroi\\Bundle\\MessageHandler\\', '../src/MessageHandler/');
    $services->get(QueueLogoutTokenHandler::class)->tag('beffroi.logout_channel');
    $services->set(BeffroiSchedule::class);
    // what tells a user that something is waiting for them, on the lane rather than in the request the
    // client is waiting on (CIBA Core §7); what carries the word at the end of it is whatever a
    // deployment tagged "beffroi.pending_approval_channel", and the bundle tags nothing
    $services->set(QueuedPendingApprovalNotifier::class);
    $services->alias(PendingApprovalNotifierInterface::class, QueuedPendingApprovalNotifier::class);
    $services->get(TellUserOfPendingApprovalHandler::class)->args([
        '$channels' => tagged_iterator('beffroi.pending_approval_channel'),
    ]);
    // what carries a logout token to a client, and what says the provider gave up on one (§4.9)
    $services->set(LogoutTokenSender::class);
    // what tells a client that a backchannel request it made has been answered (CIBA Core §10.2)
    $services->set(ClientNotificationSender::class);
    $services->set(LogoutTokenGivenUpListener::class);
    // how long a notification the provider carries to a third party is tried again: the policy the
    // application gives to the transport of that lane, and the one thing that says so
    $services->set(NotificationRetryPolicy::class);
    // What every transport encodes with (MessengerContract::SERIALIZER, decision 0020): the body sealed to
    // the message key of the tenant, the stamps in headers. Named by its identifier because the
    // configuration of the component names a service, and that identifier is in the contract.
    $services->set(MessengerContract::SERIALIZER, SealedBodySerializer::class)->args([
        service(TenantProvider::class),
        service(MessageBodySealerInterface::class),
        service(MessageBodyOpenerInterface::class),
    ]);

    // The bundle: security (architecture §5.4); the application names these in its firewall
    $services->set(IdentityUserProvider::class);
    $services->set(CorePasswordHasher::class);
    $services->set(UserChecker::class);
    $services->set(InteractionLoginHandler::class);
    $services->set(LoginSuccessListener::class)->args(['$logins' => tagged_iterator('beffroi.login.dated')]);
    $services->set(LoginFailureListener::class)->args(['$logins' => tagged_iterator('beffroi.login.refusal')]);
    // the three logins of the firewall, each an authenticator of its own, each handing what it reads to a
    // use case of the core, where the order of a login is written once (issue #130)
    $services->set(PasswordLoginAuthenticator::class);
    $services->set(PasskeyLoginAuthenticator::class);
    // a password of a user who holds a second factor is held until the code, verified by the third authenticator of the firewall
    $services->set(SecondFactorGate::class);
    $services->set(TotpLoginAuthenticator::class);
    // the assertion consumer service of the SAML service provider of the tenant, a fourth login of the firewall
    // (beffroi/saml S-52); its use case and its login are wired by the SAML section when the service provider is enabled
    $services->set(UpstreamAssertionAuthenticator::class);
    // what the logins of the firewall prove, read by the listener and announced by the discovery (decision 0010):
    // one class per login, and what is tagged is what the provider announces
    // "beffroi.login" is every login; "beffroi.login.refusal" is those whose refusals the listener
    // announces, the form login and the second step announcing their own through the core;
    // "beffroi.login.dated" is those that date the credential they proved, which the core does for the
    // two it verifies itself (issue #130)
    // "beffroi.login.offered" is those a browser starts a login with, which the login page shows by kind
    // and the floor of the tenant filters (issue #327): the code of a second step starts none
    $services->set(PasswordLogin::class)->tag('beffroi.login')->tag('beffroi.login.offered');
    $services->set(PasskeyLogin::class)->tag('beffroi.login')->tag('beffroi.login.refusal')->tag('beffroi.login.dated')->tag('beffroi.login.offered');
    $services->set(TotpLogin::class)->tag('beffroi.login');
    $services->set(PassportProofs::class)->args([tagged_iterator('beffroi.login')]);
    $services->set(OfferedLogins::class)->args([tagged_iterator('beffroi.login.offered')]);
    $services->alias(ProvableMethodsInterface::class, PassportProofs::class);
    // the attempts at a code and at a password, counted per user by the two limiters the bundle declares in the framework (architecture §3.4)
    $services->set('beffroi.security.code_attempts', RateLimitedAttempts::class)->args([service('limiter.' . RateLimitedAttempts::CODE_LIMITER)]);
    $services->alias(CodeAttemptLimiterInterface::class, 'beffroi.security.code_attempts');
    $services->set('beffroi.security.password_attempts', RateLimitedAttempts::class)->args([service('limiter.' . RateLimitedAttempts::PASSWORD_LIMITER)]);
    $services->alias(PasswordAttemptLimiterInterface::class, 'beffroi.security.password_attempts');
    // The list of compromised passwords NIST SP 800-63B §3.1.1.2 asks a password to be compared against
    // (issue #552): the range endpoint of Pwned Passwords, where five characters of a SHA-1 leave and the
    // comparison is local. There is no option to turn it on and no second adapter to alias: a deployment
    // that names no endpoint asks nobody and says so where it is configured (PasswordsSection), as one
    // that names no GeoIP licence key says an address and no place; the core keeps a null one for whoever
    // wires the core by hand. The listener is the one place a login orders a lookup, and it orders it on
    // the lane: a login keeps no third party on it.
    $services->set(PwnedPasswords::class)->args([
        '$endpoint' => '',
        '$timeout' => PasswordsSection::DEFAULT_TIMEOUT,
    ]);
    $services->alias(BreachedPasswordsInterface::class, PwnedPasswords::class);
    $services->set(BreachedPasswordListener::class);
    // a KMS that does not answer or refuses is a 503 wherever it stands on the path of a request (architecture §3.3)
    $services->set(KmsUnavailableListener::class);

    // The bundle: the two budgets that bound a load (decision 0014), the numbers filled in by the
    // configuration and the count kept in a pool of its own, shared by the processes of the OP: what one
    // origin sends, counted on every route of the two planes before any work, and what one authenticated
    // client asks, counted where the module proves its identifier. A refusal is one shape for both.
    $services->set('beffroi.load.storage', CacheStorage::class)->args([service('beffroi.load')]);
    $services->set('beffroi.load.' . LoadBudget::ORIGIN, LoadBudget::class)->args([
        '$name' => LoadBudget::ORIGIN,
        '$storage' => service('beffroi.load.storage'),
    ]);
    $services->set('beffroi.load.' . LoadBudget::CLIENT, LoadBudget::class)->args([
        '$name' => LoadBudget::CLIENT,
        '$storage' => service('beffroi.load.storage'),
    ]);
    $services->set(OriginLoadListener::class)->args([service('beffroi.load.' . LoadBudget::ORIGIN)]);
    $services->set(RateLimitedClientLoad::class)->args([service('beffroi.load.' . LoadBudget::CLIENT)]);
    $services->alias(ClientLoadBudgetInterface::class, RateLimitedClientLoad::class);
    $services->set(LoadRefusal::class);
    $services->set(LoadRefusalListener::class);

    // The bundle: persistence (architecture §5.3); no service holds a Tenant, an entity is not a service
    $services->set(EntityManagers::class);
    $services->set(TenantProvider::class)->tag('kernel.reset', [
        'method' => 'reset',
    ])->tag('doctrine.event_listener', [
        'event' => 'onClear',
    ]);
    // the tenant of the unit of work in progress, for the few callers that receive none in a parameter
    // (decision 0018): a Doctrine type takes it from here, and so does what reads whether somebody is
    // signed in before there is any tenant at all (issue #485)
    $services->alias(AmbientTenantInterface::class, TenantProvider::class);
    $services->set(TenantSynchronizer::class);
    $services->set(ClientResolver::class)->tag('doctrine.orm.entity_listener');
    $services->set(DoctrineUserRepository::class);
    $services->alias(UserRepositoryInterface::class, DoctrineUserRepository::class);
    // writes that are one fact, kept all or none (issue #781): a person an upstream provider creates and the
    // linked identity that names it
    $services->set(DoctrineAtomicWrites::class);
    $services->alias(AtomicWritesInterface::class, DoctrineAtomicWrites::class);
    // the identities a user has at an upstream provider (decision 0002), which is what the subject of an
    // assertion of a trusted issuer resolves through (RFC 7523 §2.1)
    $services->set(DoctrineLinkedIdentityRepository::class);
    $services->alias(LinkedIdentityRepositoryInterface::class, DoctrineLinkedIdentityRepository::class);
    // the browsers of a user this provider may push to (decision 0002, §5.6)
    $services->set(DoctrinePushSubscriptionRepository::class);
    $services->alias(PushSubscriptionRepositoryInterface::class, DoctrinePushSubscriptionRepository::class);
    $services->alias(CanPageActiveSubscriptionsInterface::class, DoctrinePushSubscriptionRepository::class);
    $services->set(DoctrineCredentialRepository::class);
    $services->alias(CredentialRepositoryInterface::class, DoctrineCredentialRepository::class);
    $services->alias(CanPageCredentialsInterface::class, DoctrineCredentialRepository::class);
    $services->alias(CanForgetCredentialsInterface::class, DoctrineCredentialRepository::class);
    // what lets one person reach one enrolment without a session (issue #613); a ticket spent or out of
    // time can no longer do anything and is swept with the other dead rows (issue #177)
    $services->set(DoctrineEnrolmentTicketRepository::class)->tag('beffroi.dead_records');
    $services->alias(EnrolmentTicketRepositoryInterface::class, DoctrineEnrolmentTicketRepository::class);
    // what a tenant decided of itself, written by the acts that change the row (issue #327); what the
    // configuration says of it is TenantSynchronizer's
    $services->set(DoctrineTenantRepository::class);
    $services->alias(TenantRepositoryInterface::class, DoctrineTenantRepository::class);
    // the bounded delete the stores of a dead row make (issue #177), and what the two rows a token still
    // needs are kept for, both numbers handed over by TokensSection from the nodes the issuers read
    $services->set(BoundedDelete::class);
    $services->set(WhatATokenStillNeeds::class);
    // and the step itself, which asks each tagged store what it may drop and knows no table: a kind of row
    // the provider starts keeping is a store tagged above and nothing edited here
    $services->set(DeadRecordRemoval::class)->args([tagged_iterator('beffroi.dead_records')]);

    // and the stores it asks: the ones that hold a row the provider keeps past the moment it stops working,
    // each answering for its own rows and for nobody else's (issue #177). The session is asked last, and
    // nothing of the result follows from that order: the rows of a login name it under a foreign key that
    // cascades, and its own instant is reached after theirs, so they are gone before it either way. Asked
    // last, they are gone because the store that holds them said so, and counted where they were dropped.
    $services->set(DoctrineAuthenticationSessionRepository::class)->tag('beffroi.dead_records', [
        'priority' => -100,
    ]);
    $services->alias(AuthenticationSessionRepositoryInterface::class, DoctrineAuthenticationSessionRepository::class);
    $services->alias(CanPageActiveSessionsInterface::class, DoctrineAuthenticationSessionRepository::class);
    $services->set(DoctrineInteractionRepository::class)->tag('beffroi.dead_records');
    $services->alias(InteractionRepositoryInterface::class, DoctrineInteractionRepository::class);
    // the three stores that carry a grant, each one tagged so that the reader of what a token descends
    // from asks them all and knows no flow by name (architecture §4.6)
    $services->set(DoctrineAuthorizationCodeRepository::class)->tag('beffroi.oidc.grant_record')->tag('beffroi.dead_records');
    $services->alias(AuthorizationCodeRepositoryInterface::class, DoctrineAuthorizationCodeRepository::class);
    // the grants of a session name the clients to tell it ended (Back-Channel Logout 1.0 §2.6)
    $services->alias(LoggedInClientsInterface::class, DoctrineAuthorizationCodeRepository::class);
    $services->set(DoctrinePushedAuthorizationRecordRepository::class)->tag('beffroi.dead_records');
    $services->alias(PushedAuthorizationRecordRepositoryInterface::class, DoctrinePushedAuthorizationRecordRepository::class);
    $services->set(DoctrineDeviceAuthorizationRecordRepository::class)->tag('beffroi.oidc.grant_record')->tag('beffroi.dead_records');
    $services->alias(DeviceAuthorizationRecordRepositoryInterface::class, DoctrineDeviceAuthorizationRecordRepository::class);
    $services->set(DoctrineBackchannelAuthenticationRecordRepository::class)->tag('beffroi.oidc.grant_record')->tag('beffroi.dead_records');
    $services->alias(BackchannelAuthenticationRecordRepositoryInterface::class, DoctrineBackchannelAuthenticationRecordRepository::class);
    $services->set(DoctrineRefreshTokenRepository::class)->tag('beffroi.dead_records');
    $services->alias(RefreshTokenRepositoryInterface::class, DoctrineRefreshTokenRepository::class);
    $services->alias(RefreshTokensOfAConsentInterface::class, DoctrineRefreshTokenRepository::class);
    $services->set(DoctrineAccessTokenRepository::class)->tag('beffroi.dead_records');
    $services->alias(AccessTokenRepositoryInterface::class, DoctrineAccessTokenRepository::class);
    $services->alias(CanRevokeAccessTokensByConsentInterface::class, DoctrineAccessTokenRepository::class);
    $services->alias(CanRevokeAccessTokensBySessionInterface::class, DoctrineAccessTokenRepository::class);
    $services->set(DoctrineConsentRepository::class);
    $services->alias(ConsentRepositoryInterface::class, DoctrineConsentRepository::class);
    // what the page of the account lists, read past the profiler: it is no interaction
    $services->alias(ActiveConsentsInterface::class, DoctrineConsentRepository::class);
    $services->alias(CanPageActiveConsentsInterface::class, DoctrineConsentRepository::class);

    // The core: keys
    $services->set(EnvelopeKeySealer::class);
    $services->alias(KeySealerInterface::class, EnvelopeKeySealer::class);
    $services->set(EnvelopeSecretSealer::class);
    $services->alias(SecretSealerInterface::class, EnvelopeSecretSealer::class);
    $services->set(FileTenantKeyRepository::class);
    $services->alias(TenantKeyRepositoryInterface::class, FileTenantKeyRepository::class);
    // What a process holds open of the private halves, which the provider tells what is no longer an
    // answer: one object for the life of the process, so a worker asks the KMS once per key (decision
    // 0018, architecture §3.3)
    $services->set(OpenedKeys::class);
    $services->set(SealedKeyProvider::class);
    $services->alias(SigningKeyProviderInterface::class, SealedKeyProvider::class);
    $services->alias(DecryptionKeyProviderInterface::class, SealedKeyProvider::class);
    $services->alias(PublicKeySetProviderInterface::class, SealedKeyProvider::class);
    $services->alias(ApplicationServerKeyProviderInterface::class, SealedKeyProvider::class);
    $services->alias(KeptSigningKeyProviderInterface::class, SealedKeyProvider::class);
    $services->alias(KeptDecryptionKeyProviderInterface::class, SealedKeyProvider::class);
    $services->alias(MessageKeyProviderInterface::class, SealedKeyProvider::class);
    // The algorithms the provider signs with: one class per algorithm, tagged; the first tagged one is
    // the default, the one an access token, a signed introspection response and a client that registered
    // none are signed with. A new algorithm is a class and a line here, and the discovery document, the
    // key commands and the signer follow on their own. RS256 is mandatory (OIDC Core §15.1) and FAPI 2.0
    // §5.2.2 refuses it: a deployment that follows that profile drops this line and keeps the others.
    $services->set(RsaKeyBits::class);
    $services
        ->set(Rs256::class)
        ->args([service(RsaKeyBits::class)])
        ->tag('beffroi.signature_algorithm');
    $services
        ->set(Ps256::class)
        ->args([service(RsaKeyBits::class)])
        ->tag('beffroi.signature_algorithm');
    $services->set(Es256::class)->tag('beffroi.signature_algorithm');
    $services->set(EdDsa::class)->tag('beffroi.signature_algorithm');
    $services->set(JoseSignatureAlgorithms::class)->args([tagged_iterator('beffroi.signature_algorithm')]);
    $services->alias(SignatureAlgorithmsInterface::class, JoseSignatureAlgorithms::class);
    // The algorithms a client encrypts to the provider with, wired the same way: the "alg" that wraps or
    // agrees on the content encryption key, and the "enc" that encrypts the payload. RFC 8725 §3.4 keeps
    // RSA1_5 out, and a deployment nobody encrypts to drops these lines: it then generates no encryption
    // key, publishes none and announces none, the document and the decrypter reading this one list.
    $services->set(EcdhEsA256Kw::class)->tag('beffroi.key_encryption_algorithm');
    $services
        ->set(RsaOaep256::class)
        ->args([service(RsaKeyBits::class)])
        ->tag('beffroi.key_encryption_algorithm');
    $services->set(A256Gcm::class)->tag('beffroi.content_encryption_algorithm');
    $services->set(JoseKeyEncryptionAlgorithms::class)->args([tagged_iterator('beffroi.key_encryption_algorithm')]);
    $services->alias(KeyEncryptionAlgorithmsInterface::class, JoseKeyEncryptionAlgorithms::class);
    $services->set(JoseContentEncryptionAlgorithms::class)->args([tagged_iterator('beffroi.content_encryption_algorithm')]);
    $services->alias(ContentEncryptionAlgorithmsInterface::class, JoseContentEncryptionAlgorithms::class);
    $services->set(JoseEncryptionAlgorithms::class);
    // The algorithms of the keys the tenant hands out itself rather than publishing in its JWK Set
    // (RFC 8292 §2): wired by the deployment that reaches its users by push and by no other, so that a
    // deployment that does not draws no such key and has no page that would hand one out (§5.6); the
    // web push section leaves it dormant otherwise.
    $services->set(Vapid::class);
    $services->set(JoseApplicationServerAlgorithms::class)->args([tagged_iterator('beffroi.application_server_algorithm')]);
    $services->alias(ApplicationServerAlgorithmsInterface::class, JoseApplicationServerAlgorithms::class);
    // The algorithm of the key the tenant seals what leaves the process to (decision 0020): kept and
    // never published, so a reader of the discovery document cannot seal a body this provider would open.
    // The pair it draws and the JOSE pair a sealed body carries are wired here rather than autowired,
    // because two key encryption algorithms implement that interface, and they are services of their own
    // rather than the ones above: what seals a message does not depend on a deployment that clients
    // encrypt nothing to having kept them.
    $services
        ->set(MessageSeal::class)
        ->args([inline_service(EcdhEsA256Kw::class), inline_service(A256Gcm::class)])
        ->tag('beffroi.message_sealing_algorithm');
    $services->set(JoseMessageSealingAlgorithms::class)->args([tagged_iterator('beffroi.message_sealing_algorithm')]);
    $services->alias(MessageSealingAlgorithmsInterface::class, JoseMessageSealingAlgorithms::class);
    // The algorithm of the key the tenant signs its SAML messages with (beffroi/saml, spec/saml.md S-1): an RSA pair
    // of the size above, kept out of the JWK Set and published as a certificate in the metadata of its identity
    // provider. The SAML section of the configuration tags it when the deployment enables the identity provider, and
    // nothing else does, so that a deployment that serves no SAML draws no such key; the section leaves it dormant
    // otherwise.
    $services->set(SamlSigning::class)->args([service(RsaKeyBits::class)]);
    $services->set(JoseSamlSigningAlgorithms::class)->args([tagged_iterator(JoseSamlSigningAlgorithms::TAG)]);
    // the keys the upstream SAML identity providers encrypt for, one algorithm per provider, tagged by what declares
    // the provider (beffroi/saml, spec/saml.md S-64)
    $services->set(JoseSamlEncryptionAlgorithms::class)->args([tagged_iterator(JoseSamlEncryptionAlgorithms::TAG)]);
    $services->set(JwtLibraryMessageBodySealer::class);
    $services->alias(MessageBodySealerInterface::class, JwtLibraryMessageBodySealer::class);
    $services->set(JwtLibraryMessageBodyOpener::class);
    $services->alias(MessageBodyOpenerInterface::class, JwtLibraryMessageBodyOpener::class);
    // What a key may be generated for, the registry of each use read as one: the key commands and the key
    // files resolve an algorithm name against this, whatever the key is published for. The order is the
    // one it lists and the one its refusals are read in, the signatures first.
    //
    // Each registry is a family of keys and comes with the schedule its keys rotate by (issue #738): the
    // JOSE families share the staging delay and the age of "beffroi.keys", the SAML signing key has its
    // own, counted in days (beffroi/saml, spec/saml.md S-12), which the keys the upstream SAML identity
    // providers encrypt for read too (S-64). The two schedules are built from the configuration by the
    // sections that own it (KeysSection, SamlSection); the staging and the succession of a key read the
    // schedule of its family here, and nowhere else.
    $services->set(JoseKeyAlgorithms::class)->args([[
        inline_service(JoseKeyFamily::class)->args([service(JoseSignatureAlgorithms::class), service('beffroi.keys.rotation_schedule')]),
        inline_service(JoseKeyFamily::class)->args([service(JoseKeyEncryptionAlgorithms::class), service('beffroi.keys.rotation_schedule')]),
        inline_service(JoseKeyFamily::class)->args([service(JoseApplicationServerAlgorithms::class), service('beffroi.keys.rotation_schedule')]),
        inline_service(JoseKeyFamily::class)->args([service(JoseMessageSealingAlgorithms::class), service('beffroi.keys.rotation_schedule')]),
        inline_service(JoseKeyFamily::class)->args([service(JoseSamlSigningAlgorithms::class), service('beffroi.saml.rotation_schedule')]),
        inline_service(JoseKeyFamily::class)->args([service(JoseSamlEncryptionAlgorithms::class), service('beffroi.saml.rotation_schedule')]),
    ]]);
    $services->alias(KeyAlgorithmsInterface::class, JoseKeyAlgorithms::class);
    $services->alias(RotationSchedulesInterface::class, JoseKeyAlgorithms::class);
    // The algorithms a section of the configuration leaves off, each tagged by the section that owns it: what the key
    // files read past, so that a key drawn before its capability was turned off waits for it to be turned on again; and
    // the key of an upstream SAML identity provider no longer declared, whose algorithm nothing is left to tag
    $services->set(DormantKeyAlgorithms::class)->args([
        tagged_iterator(DormantKeyAlgorithms::TAG),
        [SamlEncryptionAlgorithmInterface::NAME_PREFIX],
    ]);
    $services->set(JwtLibraryKeyPairGenerator::class);
    $services->alias(KeyPairGeneratorInterface::class, JwtLibraryKeyPairGenerator::class);
    $services->set(JwtLibraryJwsSigner::class);
    $services->alias(JwsSignerInterface::class, JwtLibraryJwsSigner::class);
    $services->set(JwtLibraryJwsVerifier::class);
    $services->alias(JwsVerifierInterface::class, JwtLibraryJwsVerifier::class);
    $services->set(JwtLibraryJweDecrypter::class);
    $services->alias(JweDecrypterInterface::class, JwtLibraryJweDecrypter::class);
    // The four steps of the life of a key, one class each (architecture §3.3): what stages, what takes
    // over, what stages a successor nobody asked for, what retires.
    //
    // The modules tag the kinds of artifact bound to a key, each naming the use it holds back, and the
    // window a retiring key holds the JWK Set open for is read from them in one place: the take-over dates
    // a retirement with it and the succession compares the age of a key with it.
    $services->set(RetirementWindow::class)->args([
        '$artifacts' => tagged_iterator('beffroi.key_bound_artifact'),
    ]);
    $services->set(NamedKey::class);
    $services->set(KeyStaging::class);
    $services->set(KeyRetirement::class);
    $services->set(KeyTakeOver::class);
    $services->set(KeySuccession::class);

    // The core: what a class of an "acr" policy requires of the proofs of a session (decision 0010), one
    // class per predicate, in the order they are wired. What a tenant may name in its vocabulary, what a
    // stored policy is read back as and what the floor of its logins is read back as all read this one
    // list, so a predicate this provider gains is a class and a line here, never a case added to an
    // enumeration. Strongest first, which is the order the default policy of the core answers in.
    $services->set(PhishingResistantHardware::class)->tag('beffroi.authentication_predicate');
    $services->set(PhishingResistant::class)->tag('beffroi.authentication_predicate');
    $services->set(TwoFactors::class)->tag('beffroi.authentication_predicate');
    $services->set(SingleFactor::class)->tag('beffroi.authentication_predicate');
    $services->set(WiredAuthenticationPredicates::class)->args([tagged_iterator('beffroi.authentication_predicate')]);
    $services->alias(AuthenticationPredicatesInterface::class, WiredAuthenticationPredicates::class);
    // Public on purpose: the DBAL types that read a stored policy and a stored floor back cannot be
    // injected into, and the bundle hands them the wiring when it boots (BeffroiBundle::boot()).
    $services->alias('beffroi.authentication_predicates', AuthenticationPredicatesInterface::class)->public();

    // The core: passwords; the hashers of one algorithm (AlgorithmPasswordHasherInterface) are tagged by hand, the registry is the port the use cases see
    // The algorithms a hash may have been made with, in the order they are wired: the first one is what a
    // new hash is made with, the others are what an import may bring. A new one is a class and a line here.
    $services->set(Argon2id::class)->tag('beffroi.password_algorithm');
    $services->set(Argon2i::class)->tag('beffroi.password_algorithm');
    $services->set(Bcrypt::class)->tag('beffroi.password_algorithm');
    $services->set(Pbkdf2Sha256::class)->tag('beffroi.password_algorithm');
    $services->set(Pbkdf2Sha512::class)->tag('beffroi.password_algorithm');
    $services->set(WiredPasswordAlgorithms::class)->args([tagged_iterator('beffroi.password_algorithm')]);
    $services->alias(PasswordAlgorithmsInterface::class, WiredPasswordAlgorithms::class);
    // Public on purpose: the DBAL types that read a hash back cannot be injected into, and the bundle
    // hands them the wiring when it boots (BeffroiBundle::boot()).
    $services->alias('beffroi.password_algorithms', PasswordAlgorithmsInterface::class)->public();

    $services->set(NativePasswordHasher::class)->tag('beffroi.password_hasher');
    $services->set(PasswordHasherRegistry::class)->args([tagged_iterator('beffroi.password_hasher'), service(PasswordAlgorithmsInterface::class)]);
    $services->alias(PasswordHasherInterface::class, PasswordHasherRegistry::class);
    // the hash a refused password is verified against when none of the user could be, computed once per process
    $services->set(DecoyHash::class);

    // The core: the WebAuthn ceremonies on webauthn-lib (architecture §3.4), on the FIDO metadata of the store
    // the console fills (the two commands), read once per process; the chains of a blob and of an attestation
    // are checked by the validator of the library, which fetches a CRL when the certificate names one and
    // lets an unreachable one pass, as the library does
    $services->set(FileMetadataBlobStore::class);
    $services->alias(MetadataBlobStoreInterface::class, FileMetadataBlobStore::class);
    $services->set(StoredMetadata::class);
    $services->alias(MetadataStatementRepository::class, StoredMetadata::class);
    $services->alias(StatusReportRepository::class, StoredMetadata::class);
    $services->set(PhpCertificateChainValidator::class);
    $services->alias(CertificateChainValidator::class, PhpCertificateChainValidator::class);
    $services->set(MetadataBlobVerifier::class);
    $services->set(WebauthnCeremonies::class);
    $services->set(WebauthnPasskeyRegistrar::class);
    $services->alias(PasskeyRegistrarInterface::class, WebauthnPasskeyRegistrar::class);
    $services->set(WebauthnPasskeyAuthenticator::class);
    $services->alias(PasskeyAuthenticatorInterface::class, WebauthnPasskeyAuthenticator::class);

    // The core: RFC 6238 on otphp (architecture §3.4)
    $services->set(OtphpTotpAlgorithm::class);
    $services->alias(TotpAlgorithmInterface::class, OtphpTotpAlgorithm::class);
    $services->set(TotpCodeMatcher::class);
    $services->set(ActiveTotp::class);

    // The core: request context enrichment (architecture §3.5). The place of an address is read in the
    // GeoLite2 databases of the deployment and nowhere else: the reader is local, so no address of this
    // provider is ever sent to anybody (issue #473, decision 0006). A deployment that holds no database
    // gets no place out of it and every flow all the same, which is why there is no option here and no
    // null adapter to alias instead; the core keeps one for whoever wires the core by hand.
    $services->set(GeoLite2Databases::class);
    $services->set(GeoLite2Refresh::class);
    $services->set(GeoLite2GeoLocator::class);
    $services->alias(GeoLocatorInterface::class, GeoLite2GeoLocator::class);
    $services->set(ProvenancePlace::class);
    $services->set(SessionProvenanceEnrichment::class);
    // the user agent of a provenance, which nothing reads yet
    $services->set(NullUserAgentParser::class);
    $services->alias(UserAgentParserInterface::class, NullUserAgentParser::class);

    // Where the identifiers of the core come from, as its clock is given to it and not read
    $services->set(SymfonyUuidGenerator::class);
    $services->alias(UuidGeneratorInterface::class, SymfonyUuidGenerator::class);
    // Where the bytes of a drawn value come from, for the same reason and in the same way (issue #245)
    $services->set(PlatformRandomness::class);
    $services->alias(RandomnessInterface::class, PlatformRandomness::class);

    // The core: use cases
    $services->set(PasswordVerification::class);
    $services->set(PasswordAuthenticator::class);
    $services->set(PendingLoginVerification::class);
    $services->set(LoginCompletion::class);
    $services->set(SecondFactorRequirement::class);
    $services->set(PasskeyEnrolment::class);
    // the ticket an administrator issues so that a person with nothing to sign in with poses a first
    // passkey (issue #613), and what a URL of it opens
    $services->set(EnrolmentTicketIssue::class);
    $services->set(EnrolmentTicketRedemption::class);
    $services->set(PresentedEnrolmentTicket::class);
    $services->set(PasskeyAuthentication::class);
    // the set of backup codes a TOTP is handed, which the enrolment and the renewal both draw (issue #629)
    $services->set(BackupCodeSet::class);
    $services->set(BackupCodesRenewal::class);
    $services->set(TotpEnrolment::class);
    $services->set(TotpAuthentication::class);
    $services->set(CredentialRevocation::class);
    // what the floor of a tenant admits to be enrolled at all, and the act that raises it (issue #327)
    $services->set(EnrolmentRefusal::class);
    $services->set(TenantHardening::class);
    $services->set(PasswordChange::class);
    // the rule §3.1.1.2 puts first, run by every path that writes a password, and the lookup of a password
    // already posed, run by the lane (issue #552)
    $services->set(BreachedPasswordRefusal::class);
    $services->set(BreachedPasswordLookup::class);
    $services->set(CredentialRenaming::class);
    $services->set(ActiveCredentials::class);
    // the one password of a person, the counterpart of ActiveTotp (issue #608)
    $services->set(ActivePassword::class);
    $services->set(SessionOpener::class);
    $services->set(OtherSessionsTermination::class);
    $services->set(SessionTerminator::class);
    $services->set(AuthenticationRefusal::class);
    $services->set(UserProvisioner::class);
    // Decision 0002: the one way a row saying a user is a subject at an upstream provider comes to exist
    // outside a flow that receives one; what needs it today is the JWT bearer grant (RFC 7523 §3)
    $services->set(IdentityLinker::class);
    // Decision 0002: the memberships a sign-in through an upstream provider asserts, mapped to the groups of
    // the tenant by the declaration of that provider, which the caller hands over (issue #782)
    $services->set(UpstreamMemberships::class);
    // Decision 0002: the person an upstream provider names at a sign-in through it, created at the first one, its
    // groups and its telephone number written in the same unit (beffroi/saml S-56)
    $services->set(JustInTimeProvisioning::class);
    $services->set(GroupProvisioner::class);
    // Decision 0029: the e-mail domains of a tenant federated to an upstream provider, read by the one rule of the
    // core (EmailDomain), where the login page sends an address of one and whom no local credential signs in; the
    // upstream providers are the SAML upstream identity providers of the tenant, none when its service provider is
    // not enabled (beffroi/saml S-60 to S-63)
    $services->set(FederatedDomains::class);
    $services->set(SamlUpstreamProviders::class);
    $services->alias(UpstreamProvidersInterface::class, SamlUpstreamProviders::class);

    // The module: every value this provider hands out and recognises again is drawn here (issue #245)
    $services->set(SecretDrawer::class);
    // RFC 8628 §3.3: a code read out loud and typed on a phone is not one of those, and is drawn beside them
    $services->set(UserCodeDrawer::class);

    // RFC 9396 §2: one class per type of authorization detail, tagged, and what is tagged is what a
    // request may ask for, what a client may register and what the discovery document announces, never an
    // enumeration kept beside them (issue #98). The bundle wires none: no type of detail is universal, a
    // type says what a client may do to what in the words of one domain, so a deployment that serves rich
    // authorization requests adds the class its own domain needs and tags it here.
    $services->set(ServedAuthorizationDetailTypes::class)->args([tagged_iterator('beffroi.oidc.authorization_detail_type')]);
    $services->alias(AuthorizationDetailsReaderInterface::class, ServedAuthorizationDetailTypes::class);
    $services->alias(ServedAuthorizationDetailTypesInterface::class, ServedAuthorizationDetailTypes::class);
    $services->alias('beffroi.authorization_detail_types', AuthorizationDetailsReaderInterface::class)->public();

    // The module: clients. One reader of the metadata a client is registered with (issue #335): a member of
    // RFC 7591 §2 is spelled there, whether a deployment declared it or a client sent it, and every source
    // of clients goes through it. What differs between them is the sources of members each reads behind the
    // ones it was given, and what each does with a refusal.
    $services->set(ClientMetadataReader::class);

    // The clients of a tenant come from every source the deployment wires (issue #334). The configuration is the
    // first of them and the clients that registered themselves are the second; a third is a class that
    // implements ClientSourceInterface and a line here, and nothing downstream learns there are several.
    // What a question about the set of clients of a tenant means is read once, in RegisteredClients: a
    // source says what it holds and never what the set of them makes true (issue #98).
    $services->set(ConfigurationClientRepository::class)->tag('beffroi.oidc.client_source')->tag('beffroi.oidc.client_inventory');
    // the second source holds rows, so it is also the one thing the removal of the clients nobody uses
    // any more asks (decision 0009); the first holds declarations and is asked nothing
    $services
        ->set(DoctrineClientRepository::class)
        ->tag('beffroi.oidc.client_source')
        ->tag('beffroi.oidc.client_inventory')
        ->tag('beffroi.oidc.unused_clients');
    $services->set(RegisteredClients::class)->args([tagged_iterator('beffroi.oidc.client_source')]);
    $services->alias(ClientRepositoryInterface::class, RegisteredClients::class);
    // RFC 9126 §5: whether the document says a request must be pushed is what the registered clients
    // require, read from the clients themselves and nowhere else (issue #98)
    $services->alias(PushedAuthorizationRequirementInterface::class, RegisteredClients::class);
    $services->alias(RegisteredResourcesInterface::class, RegisteredClients::class);
    // OIDC Discovery §3: the scopes of a tenant beyond those a claims provider serves are what its
    // clients registered, a scope that stands for no claim having nowhere else to come from (issue #278)
    $services->alias(RegisteredScopesInterface::class, RegisteredClients::class);
    $services->alias(RegisteredAccessTokenShapesInterface::class, RegisteredClients::class);
    $services->alias(UnsignedRequestObjectsInterface::class, RegisteredClients::class);
    // decision 0009: the same sources read for a person rather than for a request, which is what the
    // console lists. The two callers are disjoint, so the ports are: what resolves a client for a request
    // answers one identifier and knows no dates, and what lists them answers every client of a tenant
    $services->set(ClientInventory::class)->args([tagged_iterator('beffroi.oidc.client_inventory')]);
    $services->alias(ClientInventoryInterface::class, ClientInventory::class);
    // RFC 7591 §3.2.1: where a client the provider registers is written, which is not the port one is
    // looked up through, and the identifier it is given, drawn like every other value this provider hands
    // out and looked up before it is served
    $services->alias(ClientStoreInterface::class, DoctrineClientRepository::class);
    $services->set(ClientIdentifierDrawer::class);
    // RFC 7591, decision 0009: what a tenant does with a client that registers itself. Closed is the
    // default and closed is the absence of a policy, so a deployment that writes nothing has no
    // registration endpoint, in its document as on the wire.
    $services->set(ConfigurationClientRegistrationPolicy::class);
    $services->alias(ClientRegistrationPolicyInterface::class, ConfigurationClientRegistrationPolicy::class);
    // what authorises a registration is a class per mode, tagged, and the policy of a tenant names one of
    // them: the three modes of decision 0009 are the initial access token of RFC 7591 §1.2, the bare POST
    // of §1.3 and the statement of §2.3, and the third was a class added here and nothing edited, which is
    // what the first two were shaped for. Wiring a mode opens it for nobody: a tenant whose policy does not
    // name it never reaches it, and closed is the policy a deployment that writes nothing has.
    $services->set(DoctrineInitialAccessTokenRepository::class);
    $services->alias(InitialAccessTokenRepositoryInterface::class, DoctrineInitialAccessTokenRepository::class);
    // and the same rows read by whoever issued them rather than by the endpoint: which tokens exist,
    // what each has served, and taking one back (decision 0009). A value is in neither: the rows hold
    // digests, so what issues one is the only thing that ever sees it
    $services->alias(IssuedInitialAccessTokensInterface::class, DoctrineInitialAccessTokenRepository::class);
    $services->set(InitialAccessTokenIssuance::class);
    $services->set(InitialAccessTokenRevocation::class);
    $services->set(InitialAccessTokenAuthorization::class)->tag('beffroi.oidc.registration_mode');
    $services->set(OpenRegistrationAuthorization::class)->tag('beffroi.oidc.registration_mode');
    // RFC 7591 §2.3: the mode that crosses the boundary of an organisation, a statement signed by an
    // authority the tenant pinned in place of a credential this provider issued. Its "jti" is remembered
    // in a pool of its own until the statement expires, so that one statement registers one client and so
    // that nothing remembered here can satisfy the guard of an assertion (RFC 7523 §2.1)
    $services->set(SoftwareStatementReplayGuard::class)->args([
        inline_service(SeenOnce::class)->args([service('beffroi.software_statements')]),
    ]);
    $services->alias(SoftwareStatementReplayGuardInterface::class, SoftwareStatementReplayGuard::class);
    $services->set(SoftwareStatementVerifier::class);
    $services->set(SoftwareStatementAuthorization::class)->tag('beffroi.oidc.registration_mode');
    $services->set(RegistrationAuthorizations::class)->args([tagged_iterator('beffroi.oidc.registration_mode')]);
    // what a client registering itself is held to beyond the wiring: the scopes its tenant hands out
    // tokens for, which are the ones its document announces (issue #278)
    $services->set(RegistrationHeldToTheTenant::class);
    // OIDC Registration §5: the document behind a registered "sector_identifier_uri", read once, where a
    // registration is written and nowhere else
    $services->set(SectorIdentifierDocumentFetcher::class);
    $services->alias(SectorIdentifierDocumentFetcherInterface::class, SectorIdentifierDocumentFetcher::class);
    $services->set(RegistrationHeldToItsSector::class);
    // the one thing that reads a registration the provider is about to write, which is what makes the
    // replacement of RFC 7592 §2.2 unable to reach what the creation of RFC 7591 §3.1 could not
    $services->set(RegistrationUnderThePolicy::class);
    $services->set(ClientRegistrationHandler::class);
    // RFC 7592: a client reads, replaces and deletes itself at a URI of its own, with the token the
    // registration handed it and with nothing else. Three use cases, because a command that reads is not
    // the command that writes, over one thing that says which client a request is for.
    $services->set(ClientConfigurationAccess::class);
    $services->set(ClientConfigurationReader::class);
    $services->set(ClientConfigurationReplacement::class);
    $services->set(ClientConfigurationRemoval::class);
    // decision 0009: one thing removes a client and one event says it is gone, whichever way it went, the
    // DELETE of RFC 7592 §2.3 or the timed step below
    $services->set(RegisteredClientRemoval::class);
    // the date a stored client carries of its last use, written on the events that say somebody is using it
    $services->set(ClientUseRecording::class);
    // and what follows from it: the clients nobody uses any more are dropped, asking each source that holds
    // rows what it may drop. The source that holds declarations is not tagged and is therefore asked
    // nothing, which is how "a client a deployment declared is never deleted" is the wiring and not a
    // condition in the step.
    $services->set(UnusedClientRemoval::class)->args([tagged_iterator('beffroi.oidc.unused_clients')]);
    // how a client authenticates at the endpoints that authenticate one (RFC 6749 §2.3, OIDC Core §9):
    // one class per method, tagged, and what is tagged is what a client may register, what the endpoints
    // take and what the discovery document announces, never an enumeration kept beside them (issue #98).
    // The first tagged one is what a client that names none registers. FAPI 2.0 §5.2.2 takes
    // private_key_jwt and mTLS alone: a deployment that follows the profile drops the three lines that
    // prove a shared secret, and the provider stops taking them and stops announcing them.
    $services->set(ClientSecretBasic::class)->tag('beffroi.client_authentication_method');
    $services->set(ClientSecretPost::class)->tag('beffroi.client_authentication_method');
    $services->set(PrivateKeyJwt::class)->tag('beffroi.client_authentication_method');
    $services->set(ClientSecretJwt::class)->tag('beffroi.client_authentication_method');
    $services->set(TlsClientAuth::class)->tag('beffroi.client_authentication_method');
    $services->set(SelfSignedTlsClientAuth::class)->tag('beffroi.client_authentication_method');
    $services->set(NoAuthentication::class)->tag('beffroi.client_authentication_method');
    $services->set(ClientAuthenticationMethods::class)->args([tagged_iterator('beffroi.client_authentication_method')]);
    $services->alias(ClientAuthenticationMethodsInterface::class, ClientAuthenticationMethods::class);
    // what arrived at such an endpoint, read once into what the methods read (issue #246): the assertion
    // of RFC 7523 §2.2 included, however many of the wired methods go on to read it
    $services->set(ClientAuthenticationRequestParser::class);
    $services->set(ClientAuthenticator::class);
    // what reads an X.509 certificate and writes a distinguished name back (RFC 8705 §2.1.2): the same
    // reader on both sides, so that a name registered for a client and a name read out of a certificate
    // are written the same way and compare predictably
    $services->set(PkiFrameworkCertificateReader::class);
    $services->alias(CertificateReaderInterface::class, PkiFrameworkCertificateReader::class);
    // what reads a client assertion and what verifies it (RFC 7523 §2.2): against the keys the client
    // publishes, with the algorithms the provider is wired with, or against the secret it registered,
    // with HS256 and nothing else (RFC 8725 §3.1)
    $services->set(JwtLibraryCompactJwtReader::class);
    $services->alias(CompactJwtReaderInterface::class, JwtLibraryCompactJwtReader::class);
    $services->set('beffroi.oidc.client_assertion.signature_algorithms', AlgorithmManager::class)->factory([
        service(JoseSignatureAlgorithms::class),
        'manager',
    ]);
    $services->set(JwtLibraryJwtKeyVerifier::class)->args([service('beffroi.oidc.client_assertion.signature_algorithms')]);
    $services->alias(JwtKeyVerifierInterface::class, JwtLibraryJwtKeyVerifier::class);
    // What the provider encrypts for a client: the key management and content encryption algorithms it is
    // wired with, the same ones it opens a JWE with, read from the two registries of the core and never
    // from a list kept beside them
    $services->set('beffroi.oidc.client_encryption.algorithms', AlgorithmManager::class)->factory([service(JoseEncryptionAlgorithms::class), 'manager']);
    $services->set(JwtLibraryJweEncrypter::class)->args([service('beffroi.oidc.client_encryption.algorithms')]);
    $services->alias(JweEncrypterInterface::class, JwtLibraryJweEncrypter::class);
    $services->set(ClientDocumentIssuer::class);
    $services->set('beffroi.oidc.client_assertion.mac_algorithms', AlgorithmManager::class)->args([[inline_service(HS256::class)]]);
    $services->set(JwtLibraryClientAssertionSecretVerifier::class)->args([service('beffroi.oidc.client_assertion.mac_algorithms')]);
    $services->alias(ClientAssertionSecretVerifierInterface::class, JwtLibraryClientAssertionSecretVerifier::class);
    $services->set(ClientAssertionValidator::class);
    // the names of this provider a client assertion may name in its "aud" (issue #267): the issuer of
    // the tenant, and the two endpoints CIBA Core §7.1 adds for a client registered for a grant that
    // reaches its user itself, read from what the provider serves and from what the client registered
    $services->set(AcceptedAssertionAudiences::class);
    $services->set(ClientKeySetProvider::class)->args([service('beffroi.oidc.client_keys.provider')]);
    // the keys published behind a "jwks_uri" read back over HTTPS and kept in a pool the workers share, and
    // the "jti" of the assertions already seen kept until they expire. What reads a published set and keeps
    // it is one class, wired once per family of publisher with a pool of its own: the keys of the clients
    // here, the keys of the issuers a tenant trusts below, as the assertions of each have a pool of their
    // own. One reader of a URL serves both, so a read of an issuer costs what a read of a client costs.
    $services->set(ClientJwksFetcher::class);
    $services->alias(ClientJwksFetcherInterface::class, ClientJwksFetcher::class);
    $services->set('beffroi.oidc.client_keys.cache', ClientJwksCache::class)->args([
        '$cache' => service('beffroi.client_keys'),
    ]);
    $services->set('beffroi.oidc.client_keys.provider', PublishedKeySetProvider::class)->args([
        '$cache' => service('beffroi.oidc.client_keys.cache'),
    ]);
    $services->set(ClientAssertionReplayGuard::class)->args([
        inline_service(SeenOnce::class)->args([service('beffroi.client_assertions')]),
    ]);
    $services->alias(ClientAssertionReplayGuardInterface::class, ClientAssertionReplayGuard::class);

    // The module: an assertion read as an authorization and not as an authentication (RFC 7523 §2.1). It
    // shares nothing with the reading above: its own registration of who is trusted, its own validator and
    // its own pool of the assertions already seen, so that one reading cannot satisfy the other.
    $services->set(ConfigurationTrustedIssuers::class);
    $services->alias(TrustedIssuersInterface::class, ConfigurationTrustedIssuers::class);
    $services->set('beffroi.oidc.issuer_keys.cache', ClientJwksCache::class)->args([
        '$cache' => service('beffroi.issuer_keys'),
    ]);
    $services->set('beffroi.oidc.issuer_keys.provider', PublishedKeySetProvider::class)->args([
        '$cache' => service('beffroi.oidc.issuer_keys.cache'),
    ]);
    $services->set(IssuerAssertionValidator::class)->arg('$publishedKeys', service('beffroi.oidc.issuer_keys.provider'));
    $services->set(IssuerAssertionReplayGuard::class)->args([
        inline_service(SeenOnce::class)->args([service('beffroi.issuer_assertions')]),
    ]);
    $services->alias(IssuerAssertionReplayGuardInterface::class, IssuerAssertionReplayGuard::class);

    // The module: the proof of possession a request carries (RFC 9449), read with the reader every JWT
    // a client signs is read with and verified against the key of its own header, with the algorithms
    // the provider is wired with; the proofs already seen and the nonces it hands out live in a pool
    // the workers share, as the assertions already seen do
    $services->set(JwtLibraryProofKeyVerifier::class)->args([service('beffroi.oidc.client_assertion.signature_algorithms')]);
    $services->alias(ProofKeyVerifierInterface::class, JwtLibraryProofKeyVerifier::class);
    $services->set(CachedDpopProofReplayGuard::class)->args([
        inline_service(SeenOnce::class)->args([service('beffroi.dpop')]),
    ]);
    $services->alias(DpopProofReplayGuardInterface::class, CachedDpopProofReplayGuard::class);
    $services->set(NoDpopNonce::class);
    $services->set(CachedDpopNonce::class)->args([
        '$cache' => service('beffroi.dpop'),
    ]);
    $services->set(DpopProofValidator::class);
    $services->set(DpopProofVerifier::class);

    // The module: subject and claims. One class per kind of "sub" (OIDC Core §8), tagged, and what is
    // tagged is what a client may register and what the document announces; the first wired kind is the
    // one a client that registers none takes, so "public" stays what a client gets by writing nothing.
    // Pairwise (§8.1) is the kind a provider serving relying parties it did not choose exists to offer: a
    // deployment that wants none removes the service, and the document then names "public" alone.
    // Which sector a client is of is a class per way of saying so, tagged and read in the order they are
    // wired (issue #292): the URI it registered to say so, the host of its redirection URIs (OIDC Core
    // §8.1), and, for a client that registers no redirection URI at all, its jwks_uri (CIBA Core §4). The
    // notification endpoint of push mode is the class that would sit beside them the day this provider
    // served push. A client no wired source reads a sector for is refused at its registration rather than
    // served an identifier computed from whatever stood in.
    $services->set(RegisteredSectorIdentifier::class)->tag('beffroi.oidc.sector_identifier_source');
    $services->set(RedirectUriSectorIdentifier::class)->tag('beffroi.oidc.sector_identifier_source');
    $services->set(JwksUriSectorIdentifier::class)->tag('beffroi.oidc.sector_identifier_source');
    $services->set(SectorIdentifiers::class)->args([tagged_iterator('beffroi.oidc.sector_identifier_source')]);
    $services->alias(SectorIdentifiersInterface::class, SectorIdentifiers::class);
    $services->set(PublicSubjectIdentifierResolver::class)->tag('beffroi.oidc.subject_type');
    $services->set(PairwiseSubjectIdentifierResolver::class)->tag('beffroi.oidc.subject_type');
    $services->set(AssignedSubjectIdentifiers::class)->args([tagged_iterator('beffroi.oidc.subject_type')]);
    $services->alias(SubjectIdentifierResolverInterface::class, AssignedSubjectIdentifiers::class);
    $services->alias(PresentedSubjectReaderInterface::class, AssignedSubjectIdentifiers::class);
    $services->alias(AssignedSubjectTypesInterface::class, AssignedSubjectIdentifiers::class);
    // What a pairwise identifier is computed with and what it is read back from: a salt drawn once and
    // kept sealed beside the keys of its tenant, and the identifiers each sector has been handed
    $services->set(FilePairwiseSalt::class);
    $services->alias(PairwiseSaltInterface::class, FilePairwiseSalt::class);
    $services->set(DoctrinePairwiseSubjectRepository::class);
    $services->alias(PairwiseSubjectRepositoryInterface::class, DoctrinePairwiseSubjectRepository::class);
    // the claims of OIDC Core §5.1 and the four scopes of §5.4, closed by the specification; a deployment
    // that serves claims of its own, or a scope of its own that stands for them, wires a class beside this
    // one and edits nothing, the document announcing what the wired providers serve (issue #278)
    $services->set(StandardClaimsProvider::class)->tag('beffroi.oidc.claims_provider');
    $services->set(ServedClaims::class)->args([tagged_iterator('beffroi.oidc.claims_provider')]);
    $services->alias(ClaimsProviderInterface::class, ServedClaims::class);
    // every scope the tenant hands out tokens for, assembled once: what the document announces and what a
    // registration is held to are one set, and not two places that must agree (issues #278, #336)
    $services->set(OfferedScopes::class);
    $services->alias(OfferedScopesInterface::class, OfferedScopes::class);

    // RFC 7636 §4.2: the transformations a challenge may be made with, one class each, in the order they
    // are wired. What the document announces, what a request may name in "code_challenge_method" and what
    // a stored challenge is read back as all read this one list. "plain" is no class of the module,
    // decision 0006 refusing it, so no deployment can wire it.
    $services->set(Sha256CodeChallengeMethod::class)->tag('beffroi.oidc.code_challenge_method');
    $services->set(CodeChallengeMethods::class)->args([tagged_iterator('beffroi.oidc.code_challenge_method')]);
    $services->alias(CodeChallengeMethodsInterface::class, CodeChallengeMethods::class);
    // Public on purpose: the DBAL type that reads a stored challenge back cannot be injected into, and the
    // bundle hands it the wiring when it boots (BeffroiBundle::boot()).
    $services->alias('beffroi.code_challenge_methods', CodeChallengeMethodsInterface::class)->public();

    // The module: authorization endpoint, the pushed request the browser may come back with, and the
    // request object a client signs (RFC 9101), read with the very reader and verifier a client
    // assertion is read with, against the keys the client publishes
    $services->set(AuthorizationRequestParser::class);
    $services->set(PushedAuthorizationRequestResolver::class);
    $services->set(RequestObjectValidator::class);
    // What arrived: the object in clear, or the object inside the JWE a client encrypted to a key of the
    // tenant (RFC 9101 §6.1)
    $services->set(RequestObjectReader::class);
    $services->set(RequestObjectResolver::class);
    // CIBA Core §7.1.1: the "jti" of a backchannel request object is remembered until its "exp", in a
    // pool of its own, so that one signed request is made once (issue #269)
    $services->set(RequestObjectReplayGuard::class)->args([
        inline_service(SeenOnce::class)->args([service('beffroi.request_objects')]),
    ]);
    $services->alias(RequestObjectReplayGuardInterface::class, RequestObjectReplayGuard::class);
    $services->set(RequestObjectFetcher::class);
    $services->alias(RequestObjectFetcherInterface::class, RequestObjectFetcher::class);
    $services->set(PushedAuthorizationHandler::class);
    // RFC 8628 §3.1, §3.3: where a client with no browser starts, and what the page its user goes to asks
    $services->set(DeviceAuthorizationHandler::class);
    $services->set(DeviceApproval::class);
    // CIBA Core §7, §10.1: where a client asks for a user it names, and what the page that user answers
    // on asks. One class per way of telling the client its request was answered, tagged, and what is
    // tagged is what a client may register and what the document announces; one class per way a request
    // may name its user, of which the deployment wires the one that reads a "login_hint"
    // (BackchannelAuthenticationSection) and this the one that reads an ID token we issued
    $services->set(PollDelivery::class)->tag('beffroi.oidc.ciba_delivery_mode');
    $services->set(PingDelivery::class)->tag('beffroi.oidc.ciba_delivery_mode');
    $services->set(ServedDeliveryModes::class)->args([tagged_iterator('beffroi.oidc.ciba_delivery_mode')]);
    $services->alias(ServedDeliveryModesInterface::class, ServedDeliveryModes::class);
    $services->set(IdTokenUserHint::class)->tag('beffroi.oidc.ciba_user_hint');
    // the two ways of reading a "login_hint" the bundle ships, of which the deployment tags one per side
    // it is read on, this one and the login page (InteractionSection, LoginHintReadings): two things
    // reading one parameter would be a wiring with two answers to one question
    $services->set(SubjectLoginHint::class);
    $services->set(UsernameLoginHint::class);
    $services->set(UserHints::class)->args([tagged_iterator('beffroi.oidc.ciba_user_hint')]);
    $services->set(SignedBackchannelRequest::class);
    $services->set(BackchannelAuthenticationHandler::class);
    // what a backchannel request asks of the authentication of whoever answers it (issue #266)
    $services->set(ApprovalAuthenticationRequirement::class);
    $services->set(BackchannelApproval::class);
    // What a client may still be encrypting to a key of the tenant, which is what holds an encryption key
    // back from retiring: each one reads its lifetime where that lifetime is set (architecture §3.3)
    $services->set(RequestObjectJweKind::class)->tag('beffroi.key_bound_artifact');
    $services->set(PushedRequestJweKind::class)->tag('beffroi.key_bound_artifact');
    $services->set(IdTokenHintVerifier::class);
    // The authorization endpoint, one subject per class (issue #251): what the authentication of an
    // interaction still needs, whether a consent page is still needed, the code minted when nothing is, and
    // a handler that orchestrates the three and owns the lifecycle of the interaction.
    $services->set(AuthenticationRequirement::class);
    $services->set(AuthorizationCodeIssuer::class);
    $services->set(RequiredConsent::class);
    $services->set(AuthorizationHandler::class);
    $services->set(ConsentGranting::class);
    // OIDC Core §4: the other direction, a login this provider begins at a client rather than one a
    // client begins here. It is the authorization endpoint's counterpart and not one of its steps: what
    // it answers is a redirection to the client, which then makes the request the handler above reads
    $services->set(ThirdPartyInitiatedLoginHandler::class);
    // OIDC Core §3.1.2.1: and the way back, what the "login_hint" of that request names, read by the one
    // reading the deployment tagged for this side (InteractionSection) so the page waiting for a login
    // offers a name rather than the "sub" the client carried
    $services->set(LoginHints::class)->args([tagged_iterator('beffroi.oidc.login_hint')]);
    // and its counterpart: a consent taken back takes back what was issued under it (issue #273)
    $services->set(ConsentRevocation::class);
    // JARM §2.1: what the two signed modes deliver, minted where every other JWS of the tenant is
    $services->set(ResponseDocumentIssuer::class);

    // The module: token endpoint. One class per shape an access token is written in, tagged, and what
    // is tagged is what a client may register and what a signing key still waits for, never an
    // enumeration kept beside them (issue #239). An issuer names the shape it writes and the verifier of
    // that shape answers to the same name; the first tagged one is what a client that names none takes.
    // The person a self-contained token is about is sealed under the KMS of the tenant (issue #641), the
    // issuer of that shape writing what its verifier opens.
    $services->set(SealedPerson::class);
    $services->set(JwtAccessTokenIssuer::class)->tag('beffroi.oidc.access_token_issuer');
    $services->set(OpaqueAccessTokenIssuer::class)->tag('beffroi.oidc.access_token_issuer');
    $services->set(ServedAccessTokenShapes::class)->args([tagged_iterator('beffroi.oidc.access_token_issuer')]);
    $services->alias(AccessTokenIssuerInterface::class, ServedAccessTokenShapes::class);
    $services->alias(ServedAccessTokenShapesInterface::class, ServedAccessTokenShapes::class);
    $services->set(JwtIdTokenIssuer::class);
    $services->alias(IdTokenIssuerInterface::class, JwtIdTokenIssuer::class);
    $services->set(IdTokenJwsKind::class)->tag('beffroi.key_bound_artifact');
    $services->set(AccessTokenJwsKind::class)->tag('beffroi.key_bound_artifact');
    $services->set(ResponseDocumentJwsKind::class)->tag('beffroi.key_bound_artifact');
    $services->set(TokenIssuer::class);
    $services->set(RefreshTokenRevocation::class);
    // RFC 6749 §4.1.4: whether a response carries a refresh token, asked once for every grant that may
    $services->set(RefreshTokenDue::class);
    // RFC 9396 §7: what a token request narrows the details of its authorization to, read once for every
    // grant that spends one, as RequestedResources is for the resources beside them
    $services->set(RequestedAuthorizationDetails::class);
    // one class per grant, tagged, and what is tagged is what the token endpoint serves, what a client
    // may register and what the discovery document announces, never an enumeration kept beside them
    // (issue #173). A grant names itself and declares what it makes of a refresh token by the interfaces
    // it implements; the list is read when a question is asked of it, because a grant reads it too.
    $services->set(AuthorizationCodeGrant::class)->tag('beffroi.oidc.grant');
    $services->set(RefreshTokenGrant::class)->tag('beffroi.oidc.grant');
    $services->set(ClientCredentialsGrant::class)->tag('beffroi.oidc.grant');
    $services->set(DeviceCodeGrant::class)->tag('beffroi.oidc.grant');
    $services->set(BackchannelAuthenticationGrant::class)->tag('beffroi.oidc.grant');
    $services->set(TokenExchangeGrant::class)->tag('beffroi.oidc.grant');
    $services->set(JwtBearerGrant::class)->tag('beffroi.oidc.grant');
    $services->set(ServedGrants::class)->args([tagged_iterator('beffroi.oidc.grant')]);
    $services->alias(ServedGrantsInterface::class, ServedGrants::class);
    // one class per shape a flow has (issue #462), tagged as an opening or as a closing, and the
    // pictures are read from the grants above and from the capabilities they declare: a grant the
    // provider gains brings its picture, a grant unwired takes its picture away, and no list of flows
    // is kept beside the wiring. The order of the closings is the order a flow is read in.
    $services->set(TheUserIsSentToTheClient::class)->tag('beffroi.oidc.flow_opening');
    $services->set(TheUserIsAskedOnAnotherDevice::class)->tag('beffroi.oidc.flow_opening');
    $services->set(TheUserIsAskedThroughABackchannel::class)->tag('beffroi.oidc.flow_opening');
    $services->set(TheClientActsForItself::class)->tag('beffroi.oidc.flow_opening');
    $services->set(TheClientAsksForATokenAlone::class)->tag('beffroi.oidc.flow_opening');
    $services->set(TheProviderIsAskedWhoTheUserIs::class)->tag('beffroi.oidc.flow_closing');
    $services->set(TheResourceServerAsksWhatTheTokenIs::class)->tag('beffroi.oidc.flow_closing');
    $services->set(TheRefreshTokenIsSpent::class)->tag('beffroi.oidc.flow_closing');
    $services->set(TheTokenIsGivenBack::class)->tag('beffroi.oidc.flow_closing');
    $services->set(WiredFlowPictures::class)->args([
        service(ServedGrantsInterface::class),
        tagged_iterator('beffroi.oidc.flow_opening'),
        tagged_iterator('beffroi.oidc.flow_closing'),
    ]);
    $services->alias(FlowPicturesInterface::class, WiredFlowPictures::class);
    // one class per type of token the exchange reads (RFC 8693 §3), tagged, and what is tagged is what a
    // request may present and what a client may register, never an enumeration kept beside them
    $services->set(PresentedAccessTokenType::class)->tag('beffroi.oidc.presented_token_type');
    $services->set(PresentedTokenTypes::class)->args([tagged_iterator('beffroi.oidc.presented_token_type')]);
    $services->alias(PresentedTokenTypesInterface::class, PresentedTokenTypes::class);
    $services->set(TokenHandler::class);
    // what a token descends from, and what a consent taken back reaches, read across the records every
    // flow of the provider writes (architecture §4.3, §4.6)
    $services->set(RecordedGrants::class)->args([tagged_iterator('beffroi.oidc.grant_record')]);
    $services->alias(RecordedGrantsInterface::class, RecordedGrants::class);
    $services->alias(CanRevokeGrantsByConsentInterface::class, RecordedGrants::class);
    $services->set(CertificateConfirmationKind::class)->tag('beffroi.oidc.confirmation_kind');
    $services->set(KeyConfirmationKind::class)->tag('beffroi.oidc.confirmation_kind');
    $services->set(Confirmations::class)->args([tagged_iterator('beffroi.oidc.confirmation_kind')]);
    $services->alias(ConfirmationReaderInterface::class, Confirmations::class);
    $services->alias(ServedTokenSchemesInterface::class, Confirmations::class);
    $services->alias('beffroi.confirmations', ConfirmationReaderInterface::class)->public();

    // the other side of a shape: a token this provider writes and cannot read back is refused by the
    // verifier that collects them, where the two wired lists meet
    $services->set(JwtAccessTokenVerifier::class)->tag('beffroi.oidc.access_token_verifier');
    $services->set(OpaqueAccessTokenVerifier::class)->tag('beffroi.oidc.access_token_verifier');
    $services->set(AccessTokenVerifier::class)->args([tagged_iterator('beffroi.oidc.access_token_verifier')]);
    $services->set(PersonOfAnAccessToken::class);
    $services->set(AccessTokenInspector::class);
    $services->set(PresentedAccessTokenParser::class);

    // The module: UserInfo, introspection and revocation, discovery, logout
    $services->set(UserInfoHandler::class);
    $services->set(IntrospectionHandler::class);
    $services->set(RevocationHandler::class);
    // What the provider announces is what it is wired with: each specification it implements contributes
    // its own members, in the order the document publishes them, and a capability that arrives is a class
    // here and nothing edited elsewhere (architecture §4.8).
    $services->set(AnnouncedAlgorithms::class);
    $services->set(ProviderIdentity::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedScopes::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedClientRegistration::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedResponses::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedGrants::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedAuthenticationContext::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedIdToken::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedUserInfo::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedClientAuthentication::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedClaims::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedRequestObjects::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedPkce::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedRevocation::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedPushedAuthorization::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedDeviceAuthorization::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedBackchannelAuthentication::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedIntrospection::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedIssuerParameter::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedLogout::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedMutualTls::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedDpop::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedSignedAuthorizationResponse::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedMutualTlsEndpoints::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedProtectedResources::class)->tag('beffroi.oidc.metadata');
    $services->set(AnnouncedAuthorizationDetails::class)->tag('beffroi.oidc.metadata');
    $services->set(DiscoveryHandler::class)->args([
        '$contributors' => tagged_iterator('beffroi.oidc.metadata'),
    ]);
    $services->set(JwksHandler::class);
    // beffroi/saml: the identity provider and the service provider of the tenant, their certificates, built once per
    // process from keys the KMS opens (S-1, S-3), and their metadata under the issuer (spec/saml.md sections 6.1 and
    // 6.9); the SAML section of the configuration wires the handler of each role it enables, and of no other (S-41),
    // with what the tenant set
    $services->set(SelfSignedCertificateIssuer::class);
    $services->alias(CertificateIssuerInterface::class, SelfSignedCertificateIssuer::class);
    $services->set(ModelMetadataWriter::class);
    $services->alias(MetadataWriterInterface::class, ModelMetadataWriter::class);
    $services->set(ModelServiceProviderMetadataWriter::class);
    $services->alias(ServiceProviderMetadataWriterInterface::class, ModelServiceProviderMetadataWriter::class);
    $services->set(RouterIdentityProviderEndpoints::class);
    $services->alias(IdentityProviderEndpointsInterface::class, RouterIdentityProviderEndpoints::class);
    $services->set(SigningCertificates::class);
    // the certificates given to each upstream identity provider, in the metadata of the service provider at a URL that
    // names it (S-65), and the key that opens what it encrypted, which the assertion consumer service gives the model
    // with that provider (S-66)
    $services->set(EncryptionCertificates::class);
    $services->set(UpstreamDecryptionKeys::class);
    // beffroi/saml: the service providers of the tenant, declared in the configuration, which the SAML section hands
    // the declarations and the slug of the tenant (S-5); their metadata read by the model, fetched from a file or an
    // https URL, and the newest document accepted kept in the database, sealed (spec/saml.md section 6.2)
    // the claims an attribute is mapped from, those OpenID Connect serves (spec/saml.md S-16)
    $services->set(ProviderServedClaims::class);
    $services->alias(ServedClaimsInterface::class, ProviderServedClaims::class);
    $services->set(ConfigurationServiceProviders::class)->args([
        '$tenantSlug' => '',
        '$definitions' => [],
    ]);
    $services->alias(ServiceProvidersInterface::class, ConfigurationServiceProviders::class);
    // the claim of each mapping checked against the claims the provider serves right after the compilation, in the
    // same build; ServiceProvidersPass hands it the declarations it built (spec/saml.md S-16, section 6.2 step 1)
    $services->set(MappedClaimsWarmer::class)->args([
        '$declarations' => [],
        '$upstreamDeclarations' => [],
    ]);
    $services->set(ModelServiceProviderMetadataReader::class);
    $services->alias(ServiceProviderMetadataReaderInterface::class, ModelServiceProviderMetadataReader::class);
    $services->set(MetadataFetcher::class);
    $services->alias(MetadataFetcherInterface::class, MetadataFetcher::class);
    // the rows of the service providers, which single sign-on and single logout read through the port; the metadata
    // of every role are refreshed by one procedure (MetadataRefresh), built with the role and the rows of its table,
    // and every refresh is tagged for the hourly step of the schedule (spec/saml.md section 6.2, S-42)
    $services->set(DoctrineAcceptedMetadataRepository::class)->arg('$entity', AcceptedServiceProviderMetadata::class);
    $services->alias(AcceptedMetadataRepositoryInterface::class, DoctrineAcceptedMetadataRepository::class);
    $services->alias(CanForgetAcceptedMetadataInterface::class, DoctrineAcceptedMetadataRepository::class);
    $services->set(ServiceProviderRole::class);
    $services
        ->set('beffroi.saml.service_providers.refresh', MetadataRefresh::class)
        ->args([
            '$role' => service(ServiceProviderRole::class),
            '$accepted' => service(DoctrineAcceptedMetadataRepository::class),
        ])
        ->tag(RefreshTheSamlMetadataHandler::TAG);
    $services->set('beffroi.saml.service_providers.forgetting', AcceptedMetadataForgetting::class)->args([
        '$accepted' => service(DoctrineAcceptedMetadataRepository::class),
        '$forgetting' => service(DoctrineAcceptedMetadataRepository::class),
    ]);
    $services->get(SamlServiceProviderRefreshCommand::class)->arg('$refresh', service('beffroi.saml.service_providers.refresh'));
    $services->get(SamlServiceProviderForgetCommand::class)->arg('$forgetting', service('beffroi.saml.service_providers.forgetting'));
    // beffroi/saml: the upstream identity providers of the service provider of the tenant, declared in the
    // configuration, which the SAML section hands the declarations and the slug of the tenant (S-42), their
    // attributes filling the claims a person describes themselves with (S-45); their metadata read by the model,
    // fetched as a service provider's, refreshed by the same procedure, and the newest document accepted kept in a
    // table of their own, sealed (spec/saml.md section 6.10)
    $services->set(WiredProfileClaims::class);
    $services->alias(ProfileClaimsInterface::class, WiredProfileClaims::class);
    $services->set(ConfigurationUpstreamIdentityProviders::class)->args([
        '$tenantSlug' => '',
        '$definitions' => [],
    ]);
    $services->alias(UpstreamIdentityProvidersInterface::class, ConfigurationUpstreamIdentityProviders::class);
    $services->set(ModelUpstreamMetadataReader::class);
    $services->alias(UpstreamMetadataReaderInterface::class, ModelUpstreamMetadataReader::class);
    $services->set(UpstreamIdentityProviderRole::class);
    $services->set('beffroi.saml.identity_providers.accepted_metadata', DoctrineAcceptedMetadataRepository::class)->arg(
        '$entity',
        AcceptedUpstreamMetadata::class,
    );
    $services
        ->set('beffroi.saml.identity_providers.refresh', MetadataRefresh::class)
        ->args([
            '$role' => service(UpstreamIdentityProviderRole::class),
            '$accepted' => service('beffroi.saml.identity_providers.accepted_metadata'),
        ])
        ->tag(RefreshTheSamlMetadataHandler::TAG);
    $services->set('beffroi.saml.identity_providers.forgetting', AcceptedMetadataForgetting::class)->args([
        '$accepted' => service('beffroi.saml.identity_providers.accepted_metadata'),
        '$forgetting' => service('beffroi.saml.identity_providers.accepted_metadata'),
    ]);
    $services->get(SamlIdentityProviderRefreshCommand::class)->arg('$refresh', service('beffroi.saml.identity_providers.refresh'));
    $services->get(SamlIdentityProviderForgetCommand::class)->arg('$forgetting', service('beffroi.saml.identity_providers.forgetting'));
    $services->get(RefreshTheSamlMetadataHandler::class)->arg('$refreshes', tagged_locator(RefreshTheSamlMetadataHandler::TAG));
    // beffroi/saml: single sign-on (spec/saml.md section 6.4), a request received over either binding and validated by
    // the model, answered from the session of the browser or after its login, the request waiting in its HTTP session
    // (S-18); the assertion signed by the active SAML key of the tenant, opened by the KMS once per process to sign,
    // besides once for its certificate when the metadata are served first (S-3, S-15), its NameID computed with the
    // salt of the pairwise subjects (S-13), its attributes from the claims OpenID Connect serves
    $services->set(DeclaredServiceProviderReader::class);
    $services->set(ModelAuthnRequestReceiver::class);
    $services->alias(AuthnRequestReceiverInterface::class, ModelAuthnRequestReceiver::class);
    $services->set(TenantSigning::class)->args([
        '$algorithm' => service(SamlSigning::class),
    ]);
    $services->set(ModelSignOnResponder::class);
    $services->alias(SignOnResponderInterface::class, ModelSignOnResponder::class);
    $services->set(TenantPersistentIdentifierSalt::class);
    $services->alias(PersistentIdentifierSaltInterface::class, TenantPersistentIdentifierSalt::class);
    $services->set(AttributeRelease::class);
    $services->set(SingleSignOn::class);
    $services->set(WaitingSignOns::class);
    $services->set(SamlPostPage::class);
    $services->set(SignOnAnswers::class);
    // beffroi/saml: the request the service provider of the tenant sends an upstream identity provider for an
    // interaction of the browser (spec/saml.md S-48 to S-51), written to a single sign-on service of the accepted
    // document read back from the table of the upstream identity providers, and not of the service providers the port
    // is aliased to, signed by the SAML key of the tenant, remembered in the HTTP session of the browser under its
    // RelayState; the use case is wired by the SAML section when the service provider is enabled
    $services->set(ModelAuthnRequestSender::class)->arg('$accepted', service('beffroi.saml.identity_providers.accepted_metadata'));
    $services->alias(AuthnRequestSenderInterface::class, ModelAuthnRequestSender::class);
    $services->set(UpstreamSignOns::class);
    $services->set(UpstreamSignOnAnswer::class);
    // beffroi/saml: what a login at an upstream identity provider is asked, read from the rule of the login page,
    // whether its request forces a login and what the client still asks once the provider answered (S-49, S-58)
    $services->set(UpstreamLoginRequirement::class);
    // beffroi/saml: Single Logout started by a service provider (spec/saml.md section 6.5), a request received over
    // either binding, validated by the model and remembered in a store every worker shares, written atomically (S-23);
    // the sessions it names ended by the core as every session ends (S-25) and the answer signed by the SAML key of
    // the tenant (S-27); each service provider's part in a session recorded from the event single sign-on announces,
    // on the lane of the events (S-26)
    $services->set(DoctrineReplayStore::class);
    $services->alias(ReplayStoreInterface::class, DoctrineReplayStore::class);
    $services->set(ModelLogoutMessageReceiver::class);
    $services->alias(LogoutMessageReceiverInterface::class, ModelLogoutMessageReceiver::class);
    $services->set(ModelSignOutResponder::class);
    $services->alias(SignOutResponderInterface::class, ModelSignOutResponder::class);
    $services->set(SingleLogout::class);
    $services->set(DoctrineSessionParticipationRepository::class);
    $services->alias(SessionParticipationRepositoryInterface::class, DoctrineSessionParticipationRepository::class);
    $services->set(SessionParticipants::class);
    // beffroi/saml: Single Logout started by the identity provider (spec/saml.md section 6.6), every service provider
    // of the sessions a browser ended told through that browser, by a request signed by the SAML key of the tenant
    // (S-31), its answer read at the single logout service (S-33); the chain kept in a store every worker shares,
    // taken by one request at each step and played by the browser that began it alone, which a cookie of the provider
    // binds it to (S-32); the page of Front-Channel Logout 1.0 put before it (S-35)
    $services->set(DoctrineLogoutChainRepository::class);
    $services->alias(LogoutChainRepositoryInterface::class, DoctrineLogoutChainRepository::class);
    $services->set(ModelSignOutNotifier::class);
    $services->alias(SignOutNotifierInterface::class, ModelSignOutNotifier::class);
    $services->set(ProviderLogout::class);
    $services->set(LogoutChainCookie::class);
    $services->set(LogoutChainPages::class);
    $services->set(EndSessionRequestParser::class);
    $services->set(EndSessionHandler::class);
    $services->set(LogoutTokenIssuer::class);
    $services->set(BackChannelLogout::class);
    $services->set(SessionTokensRevocation::class);
    $services->set(FrontChannelLogout::class);
    // The two ways of telling a client that a session ended (architecture §4.9): one class per channel,
    // and what is tagged is what the discovery document announces, never an enumeration kept beside it
    $services->set(FrontChannelLogoutRenderer::class)->tag('beffroi.logout_channel');
    $services->set(LogoutChannels::class)->args([tagged_iterator('beffroi.logout_channel')]);
    $services->alias(ServedLogoutChannelsInterface::class, LogoutChannels::class);
    // how long a logout token stays on its way, from the retries of its lane and the timeout of one send
    $services->set(LogoutTokenDeliveryBudget::class);
    $services->alias(LogoutTokenDeliveryInterface::class, LogoutTokenDeliveryBudget::class);
    $services->set(LogoutTokenJwsKind::class)->tag('beffroi.key_bound_artifact');
};
