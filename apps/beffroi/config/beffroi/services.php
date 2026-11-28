<?php

declare(strict_types=1);

use App\Http\LoginAddresses;
use App\Saml\UpstreamDiscovery;
use Beffroi\Core\Port\UpstreamProvidersInterface;
use App\Saml\SamlUpstreamProviders;
use Beffroi\Core\Application\Identity\FederatedDomains;
use App\Command\DoctorCommand;
use App\Administration\AdministrationGuard;
use App\Administration\Controller\HealthController;
use App\Http\ProtectedResourceRefusals;
use App\Messenger\LaneBacklogs;
use App\Statistics\InstanceStatistics;
use Beffroi\Core\Port\CanCountActiveSessionsInterface;
use Beffroi\Core\Port\CanCountActsInterface;
use Beffroi\Core\Port\CanCountUsersInterface;
use Beffroi\Oidc\Application\Administration\AdministeredJournal;
use Beffroi\Oidc\Application\Administration\AdministeredPerson;
use Beffroi\Oidc\Application\Administration\AdministeredCredentialRevocation;
use Beffroi\Oidc\Application\Administration\AdministeredEnrolmentTicket;
use Beffroi\Oidc\Application\Administration\AdministeredPasswordTicket;
use Beffroi\Oidc\Application\Administration\AdministeredTotpTicket;
use Beffroi\Oidc\Application\Administration\AdministeredPersonCreation;
use Beffroi\Oidc\Application\Administration\AdministeredDescription;
use Beffroi\Oidc\Application\Administration\AdministeredClientRemoval;
use Beffroi\Oidc\Application\Administration\AdministeredConsents;
use Beffroi\Oidc\Application\Administration\AdministeredDisabling;
use Beffroi\Oidc\Application\Administration\AdministeredGroupCreation;
use Beffroi\Oidc\Application\Administration\AdministeredTenantContact;
use Beffroi\Oidc\Application\Administration\AdministeredGroups;
use Beffroi\Oidc\Application\Administration\AdministeredMemberships;
use Beffroi\Oidc\Application\Administration\AdministeredEnabling;
use Beffroi\Oidc\Application\Administration\AdministeredSessionEnd;
use Beffroi\Oidc\Application\Administration\AdministeredSessions;
use Beffroi\Oidc\Application\Administration\PersonDelivery;
use Beffroi\Oidc\Application\Administration\AdministratorOfARequest;
use Beffroi\Oidc\Application\Administration\PersonsOfTheTenant;
use Beffroi\Oidc\Application\Administration\PersonsDelivered;
use Beffroi\Oidc\Port\PersonsBudgetInterface;
use App\Administration\PersonsRefusalListener;
use App\Administration\RateLimitedPersonsBudget;
use App\Doctor\ClientsSignedWithHeldKeys;
use App\Doctor\ChainHoldsTogether;
use App\Doctor\NotificationsLanePatience;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Application\Secret\UserCodeDrawer;
use Beffroi\Core\Port\RandomnessInterface;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Bridge\Clock\PlatformMonotonicClock;
use Beffroi\Core\Port\MonotonicClockInterface;
use App\Account\ApplicationHoldings;
use App\Ciba\QueuedPendingApprovalNotifier;
use App\Credential\CredentialChangeChannels;
use App\Credential\MailToTheReplacedAddressChannel;
use App\Credential\RateLimitedChannelChangeWindow;
use App\Credential\SmsToTheReplacedNumberChannel;
use App\Credential\CredentialChangeNotices;
use App\Credential\QueuedCredentialChangeNotifier;
use App\Credential\WebPushCredentialChangeChannel;
use App\Credential\MailCredentialChangeChannel;
use App\Credential\SmsCredentialChangeChannel;
use Beffroi\Core\Port\CredentialChangeNotifierInterface;
use Beffroi\Core\Port\ChannelChangeWindowInterface;
use Beffroi\Core\Application\Notification\ChannelChangeNotice;
use App\Cache\SeenOnce;
use App\Client\ClientAssertionReplayGuard;
use App\Client\SoftwareStatementReplayGuard;
use App\Trust\IssuerAssertionReplayGuard;
use App\Client\RequestObjectReplayGuard;
use App\Client\ClientJwksCache;
use App\Client\ClientJwksFetcher;
use App\Client\RegistrationsReadOncePerRequest;
use App\Client\RequestObjectFetcher;
use App\Client\SectorIdentifierDocumentFetcher;
use App\Doctrine\Listener\ClientResolver;
use App\Doctrine\DoctrineAtomicWrites;
use App\Lock\LockedSections;
use App\Doctrine\EntityManagers;
use App\Doctrine\PageOfRows;
use App\Doctrine\PersonalData\DataKeysOfTheTenant;
use App\Doctrine\Repository\DoctrineAccessTokenRepository;
use App\Doctrine\Repository\BoundedDelete;
use App\Doctrine\Repository\DoctrineAuthenticationSessionRepository;
use App\Doctrine\Repository\DoctrineAuthorizationCodeRepository;
use App\Doctrine\Repository\DoctrineClientRepository;
use App\Doctrine\Repository\DoctrineInitialAccessTokenRepository;
use App\Doctrine\Repository\DoctrineConsentRepository;
use App\Doctrine\Repository\DoctrineCredentialRepository;
use App\Doctrine\Repository\DoctrinePasskeyUses;
use App\Doctrine\Repository\ConditionalCredentialWrite;
use Beffroi\Core\Port\EnrolmentTicketRepositoryInterface;
use Beffroi\Core\Port\PasswordTicketRepositoryInterface;
use Beffroi\Core\Port\TotpTicketRepositoryInterface;
use Beffroi\Core\Port\TotpUsesInterface;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketRedemption;
use Beffroi\Core\Application\Ticket\PasswordTicketIssue;
use Beffroi\Core\Application\Ticket\PasswordTicketRedemption;
use Beffroi\Core\Application\Ticket\TicketIssuing;
use Beffroi\Core\Application\Ticket\TicketRedeeming;
use Beffroi\Core\Application\Ticket\CredentialTicketRefusal;
use Beffroi\Core\Application\Ticket\TotpTicketIssue;
use Beffroi\Core\Application\Ticket\TotpTicketRedemption;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use App\Http\PresentedTicket;
use App\Http\TicketLink;
use App\Doctrine\Repository\DoctrineEnrolmentTicketRepository;
use App\Doctrine\Repository\DoctrinePasswordTicketRepository;
use App\Doctrine\Repository\DoctrineTotpTicketRepository;
use App\Doctrine\Repository\DoctrineTotpUses;
use Beffroi\Core\Port\TenantRepositoryInterface;
use Beffroi\Core\Port\CanForgetCredentialsInterface;
use Beffroi\Core\Port\PasskeyUsesInterface;
use Beffroi\Core\Application\Tenant\TenantContactAdoption;
use Beffroi\Core\Application\Tenant\TenantHardening;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use App\Http\OfferedLogins;
use App\Doctrine\Repository\DoctrineTenantRepository;
use App\Doctrine\Repository\DoctrineInteractionRepository;
use App\Doctrine\Repository\DoctrinePairwiseSubjectRepository;
use App\Doctrine\Repository\DoctrinePushedAuthorizationRecordRepository;
use App\Doctrine\Repository\DoctrineBackchannelAuthenticationRecordRepository;
use App\Doctrine\Repository\DoctrineDeviceAuthorizationRecordRepository;
use App\Doctrine\Repository\DoctrineRefreshTokenRepository;
use App\Doctrine\Repository\DoctrineLinkedIdentityRepository;
use App\Doctrine\Repository\DoctrineGroupMembershipRepository;
use App\Doctrine\Repository\DoctrineGroupRepository;
use App\Doctrine\Repository\DoctrinePersonalArchiveRepository;
use App\Http\Account\ArchiveSection;
use App\Archive\ZipArchiveContainer;
use App\Http\ArchivePage;
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
use Beffroi\Core\Port\GroupsOfATenantInterface;
use Beffroi\Core\Port\MembersOfAGroupInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Core\Port\LinkedIdentitiesOfAPersonInterface;
use Beffroi\Core\Port\PersonalArchiveRepositoryInterface;
use Beffroi\Oidc\Application\Archive\ConsentsChapter;
use App\Doctrine\Repository\DoctrineUserRepository;
use App\Doctrine\TenantProvider;
use App\Doctrine\TenantSynchronizer;
use App\Dpop\CachedDpopNonce;
use App\Dpop\CachedDpopProofReplayGuard;
use App\EndSession\FrontChannelLogoutRenderer;
use App\Fido\Conformance\ConformanceToolsAlgorithms;
use App\EndSession\LogoutChannels;
use App\EndSession\LogoutTokenDeliveryBudget;
use App\EndSession\QueuedLogoutTokenRetries;
use App\Http\AccountAccess;
use App\Http\AskedPage;
use App\Http\AskedPeriod;
use App\Http\AskedWord;
use App\Http\UntoldChange;
use App\Http\WhatWasRefused;
use App\Http\AccountHomePage;
use App\Http\Account\AccountSections;
use App\Http\Account\BreachedPasswordDemand;
use App\Http\Account\RecentProofListener;
use App\Http\Account\PasskeysSection;
use App\Http\Account\ProfileSection;
use App\Http\Account\ApprovalsSection;
use App\Http\Account\ConsentsSection;
use App\Http\Account\TwoFactorSection;
use App\Http\AuthorizationRequestReader;
use App\Http\Decision\ConsentRequiredRenderer;
use App\Http\Decision\DecisionRenderers;
use App\Http\Decision\GrantedRenderer;
use App\Http\Decision\InteractionPage;
use App\Http\Decision\LoginRequiredRenderer;
use App\Http\FapiInteractionId;
use App\Http\FormTarget;
use App\Http\ImageSource;
use App\Http\FormToken;
use App\Http\DeviceApprovalPage;
use App\Http\RecentLogin;
use App\Http\LoginTarget;
use App\Http\AuthorizationRequestReaderInterface;
use App\Http\AuthorizationResponder;
use App\Http\AuthorizationResponderInterface;
use App\Http\BrowserSession;
use App\Http\DatabaseSessions;
use App\Http\CrossSitePost;
use App\Http\CrossSiteSessionCookie;
use App\Http\BrowserPreferences;
use App\Http\ApplicationPage;
use App\Http\InteractionLocale;
use App\Http\SessionsPage;
use App\Http\ActsPage;
use App\Locale\KnownLocales;
use App\Locale\LocalePreference;
use App\Locale\AnnouncedUiLocales;
use App\Locale\ServedLocales;
use App\Locale\UserLocale;
use App\Http\InteractionPages;
use App\Http\ClientNotificationSender;
use App\Http\PendingApprovalsPage;
use App\Http\LogoutTokenSender;
use App\Http\ThirdPartyRequestsPass;
use App\Http\PasskeyOptionsStore;
use App\Http\ClaimChangesPage;
use App\Http\ProfilePage;
use App\Http\PasskeysPage;
use App\Http\PasswordPage;
use App\Http\ConsentsPage;
use App\Http\PendingLoginStore;
use App\Http\QrCode;
use App\Http\RequestContextFactory;
use App\Http\ResponseMode\AuthorizationResponseRenderers;
use App\Http\ResponseMode\FormPostResponseRenderer;
use App\Http\ResponseMode\QueryResponseRenderer;
use App\Http\ResponseMode\SignedFormPostResponseRenderer;
use App\Http\ResponseMode\SignedQueryResponseRenderer;
use App\Http\Tls\ClientCertificateResolverInterface;
use App\Http\Tls\EdgeClientCertificateResolver;
use App\Http\Tls\PresentedClientCertificate;
use App\Configuration\KeysSection;
use App\Http\TotpProvisioningSealer;
use App\Http\TotpProvisioningStore;
use App\Http\TwoFactorPage;
use App\Http\TotpSecretShown;
use App\Key\FilePairwiseSalt;
use App\Key\FileChainCheckpoints;
use App\Chain\LoggedCheckpointCopies;
use App\Chain\LoggedCut;
use App\Key\DormantKeyAlgorithms;
use App\Key\FileTenantKeyRepository;
use App\Key\KeysOpenedAtStart;
use App\Key\KmsUnavailableListener;
use App\Load\LoadBudget;
use App\Load\LoadRefusal;
use App\Load\LoadRefusalListener;
use App\Load\OriginLoadListener;
use App\Load\RateLimitedClientLoad;
use App\MessageHandler\TellUserOfPendingApprovalHandler;
use App\MessageHandler\QueueLogoutTokenHandler;
use App\Messenger\EventBusDispatcher;
use App\Messenger\FailedMessagesSealedTo;
use App\Messenger\KeysOpenedAtWorkerStart;
use App\Messenger\LaneDsn;
use App\Messenger\GivenUpListener;
use App\Messenger\MessengerContract;
use App\Messenger\NotificationRetryPolicy;
use App\Messenger\SealedBodySerializer;
use App\Plane\Plane;
use App\Routing\ProviderRoutes;
use App\Plane\PlaneRequestListener;
use App\Routing\RouterEndpointLocator;
use App\Scheduler\BeffroiSchedule;
use App\Security\BreachedPasswordListener;
use App\Security\CorePasswordHasher;
use App\Security\IdentityUserProvider;
use App\Security\InteractionLoginHandler;
use App\Security\LoginFailureListener;
use App\Security\LoginSuccessListener;
use App\Security\PasskeyLogin;
use App\Security\LoginFormToken;
use App\Security\PasskeyLoginAuthenticator;
use App\Security\UpstreamAssertionAuthenticator;
use App\Security\PasswordLoginAuthenticator;
use App\Security\PassportProofs;
use App\Security\PwnedPasswords;
use App\Security\PasswordLogin;
use App\Security\RateLimitedAttempts;
use App\Security\SecondFactorGate;
use App\Security\TotpLogin;
use App\Security\TotpLoginAuthenticator;
use App\Security\UserChecker;
use App\Tenant\TenantFactory;
use App\Locale\Moments;
use App\Locale\UserTimeZone;
use App\Doctrine\Repository\DoctrineJournal;
use App\Doctrine\Chain\DoctrineChains;
use App\Doctrine\Role\RuntimeRoleGrants;
use App\Doctrine\Chain\JournalTable;
use App\Doctrine\Chain\ClaimHistoryTable;
use App\Doctrine\Chain\DisclosureTable;
use App\Command\NamedChain;
use App\MessageHandler\SignTheChainsHandler;
use App\Identity\LocaleClaimFactory;
use App\Identity\WiredClaims;
use Beffroi\Core\Port\ClaimsInterface;
use Beffroi\Core\Application\Identity\LanguageRecording;
use Beffroi\Core\Application\Identity\SelfDescription;
use Beffroi\Core\Application\Identity\PersonDescription;
use Beffroi\Core\Application\Identity\PersonDisabling;
use Beffroi\Core\Application\Identity\PersonEnabling;
use Beffroi\Core\Application\Identity\Member\AddressMember;
use Beffroi\Core\Application\Identity\Member\EmailMember;
use Beffroi\Core\Application\Identity\Member\EmailVerifiedMember;
use Beffroi\Core\Application\Identity\Member\PhoneNumberVerifiedMember;
use Beffroi\Core\Application\Identity\Member\UsernameMember;
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
use Beffroi\Core\Application\Author\Authors;
use Beffroi\Core\Domain\Author\AdministratorKind;
use Beffroi\Core\Domain\Author\ClientKind;
use Beffroi\Core\Domain\Author\DirectoryKind;
use Beffroi\Core\Domain\Author\HostKind;
use Beffroi\Core\Domain\Author\PersonKind;
use Beffroi\Core\Domain\Author\UnauthenticatedKind;
use Beffroi\Core\Domain\Author\UpstreamKind;
use Beffroi\Core\Port\KindsOfAuthorInterface;
use Beffroi\Core\Port\AuthorReaderInterface;
use Beffroi\Core\Application\Session\ProvedMethods;
use Beffroi\Core\Application\Session\ProvenancePlace;
use Beffroi\Core\Application\Session\SessionProvenanceEnrichment;
use Beffroi\Core\Application\Journal\JournalRetention;
use Beffroi\Core\Application\Chain\ChainWalk;
use Beffroi\Core\Application\Chain\ChainCheckpoints;
use Beffroi\Core\Application\Chain\ChainCut;
use Beffroi\Core\Application\Chain\ChainRelinking;
use Beffroi\Core\Application\Chain\ChainSignature;
use Beffroi\Core\Application\Chain\ChainVerification;
use Beffroi\Core\Domain\Journal\JournalChain;
use Beffroi\Core\Domain\Identity\ClaimHistoryChain;
use Beffroi\Oidc\Domain\Disclosure\DisclosureChain;
use App\Doctrine\Repository\DoctrineDisclosures;
use Beffroi\Oidc\Application\Archive\DisclosuresChapter;
use Beffroi\Oidc\Application\Disclosure\DisclosureRecording;
use Beffroi\Oidc\Application\Disclosure\DisclosureRetention;
use Beffroi\Oidc\Port\DisclosuresInterface;
use Beffroi\Oidc\Port\DisclosuresOfAPersonInterface;
use Beffroi\Core\Application\Record\DeadRecordRemoval;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use Beffroi\Core\Port\CanFindUnendedSessionsInterface;
use Beffroi\Core\Port\CanPageActiveSessionsInterface;
use Beffroi\Core\Port\CanPageActiveSubscriptionsInterface;
use Beffroi\Core\Port\CanPageActsOfAPersonInterface;
use Beffroi\Core\Port\CanPageChangesOfAPersonInterface;
use Beffroi\Core\Port\CanPageCredentialsInterface;
use App\Doctrine\Repository\DoctrineClaimHistory;
use Beffroi\Core\Application\Archive\Chapter\ChangesChapter;
use Beffroi\Core\Application\Identity\ClaimHistoryRetention;
use Beffroi\Core\Port\AmbientTenantInterface;
use Beffroi\Core\Port\ChangesOfAPersonInterface;
use Beffroi\Core\Port\ClaimHistoryInterface;
use Beffroi\Core\Port\JournalInterface;
use App\Twig\ClientNameExtension;
use App\Twig\LocaleExtension;
use App\Twig\MomentExtension;
use App\Twig\AuthenticatorModelExtension;
use App\Twig\AuthorExtension;
use App\Twig\DeviceExtension;
use App\Twig\PlaceExtension;
use App\Twig\TenantExtension;
use App\Webauthn\DocumentDownload;
use App\Webauthn\FileAuthenticatorListStore;
use App\Webauthn\FileMetadataBlobStore;
use App\Webauthn\RevocationListClient;
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
use Beffroi\Core\Application\Credential\DeclaredModels;
use Beffroi\Core\Application\Credential\AuthenticatorModels;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Credential\BreachedPasswordLookup;
use Beffroi\Core\Application\Credential\BreachedPasswordRefusal;
use Beffroi\Core\Application\Credential\PasswordChange;
use Beffroi\Core\Application\Credential\CredentialRenaming;
use Beffroi\Core\Application\Credential\CredentialRevocation;
use Beffroi\Core\Application\Administration\Administrators;
use Beffroi\Core\Application\Group\GroupProvisioner;
use Beffroi\Core\Application\Group\LocalMemberships;
use Beffroi\Core\Bridge\Configuration\ConfigurationAdministratorGroups;
use Beffroi\Core\Port\AdministratorGroupsInterface;
use Beffroi\Core\Application\Group\UpstreamMemberships;
use Beffroi\Core\Application\Identity\IdentityLinker;
use Beffroi\Core\Application\Identity\JustInTimeProvisioning;
use Beffroi\Core\Application\Identity\PersonCreation;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Application\Key\ActiveKeptSigningKeys;
use Beffroi\Core\Application\Key\ActiveSigningKeys;
use Beffroi\Core\Application\Key\HeldSigningAlgorithms;
use Beffroi\Core\Application\Key\ApplicationServerKeysInService;
use Beffroi\Core\Application\Key\KeptDecryptionKeysInService;
use Beffroi\Core\Application\Key\KeyRetirement;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Application\Key\KeySuccession;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Application\Key\MessageKeysInService;
use Beffroi\Core\Application\Key\NamedKey;
use Beffroi\Core\Application\Key\PublishedDecryptionKeys;
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
use App\Saml\JoseSamlEncryptionAlgorithms;
use App\Saml\JoseSamlSigningAlgorithms;
use App\Saml\MappedClaimsWarmer;
use App\Saml\ProviderServedClaims;
use App\Saml\SamlPostPage;
use App\Saml\SignOnAnswers;
use App\Saml\TenantPersistentIdentifierSalt;
use App\Saml\WaitingSignOns;
use Beffroi\Core\Port\KeptDecryptionKeyProviderInterface;
use Beffroi\Core\Port\KeptSigningKeyProviderInterface;
use Beffroi\Saml\Application\SingleSignOn\AttributeRelease;
use Beffroi\Saml\Application\SingleSignOn\SingleSignOn;
use Beffroi\Saml\Bridge\Model\ModelAuthnRequestReceiver;
use Beffroi\Saml\Bridge\Model\DeclaredServiceProviderReader;
use Beffroi\Saml\Bridge\Model\ModelAuthnRequestSender;
use Beffroi\Saml\Port\AuthnRequestSenderInterface;
use App\Saml\UpstreamLoginRequirement;
use App\Saml\UpstreamSignOnAnswer;
use App\Saml\UpstreamSignOnReferences;
use App\Saml\UpstreamSignOns;
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
use App\Doctrine\Repository\DoctrineReplayStore;
use App\Doctrine\Repository\DoctrineSessionParticipationRepository;
use Beffroi\Saml\Bridge\Model\ModelSignOnResponder;
use Beffroi\Saml\Port\AuthnRequestReceiverInterface;
use Beffroi\Saml\Port\PersistentIdentifierSaltInterface;
use Beffroi\Saml\Port\SignOnResponderInterface;
use App\Saml\RouterIdentityProviderEndpoints;
use App\Saml\SamlSigning;
use App\Saml\LogoutChainCookie;
use App\Saml\LogoutChainPages;
use App\Doctrine\Repository\DoctrineLogoutChainRepository;
use Beffroi\Saml\Application\Metadata\EncryptionCertificates;
use Beffroi\Saml\Application\Metadata\SigningCertificates;
use Beffroi\Saml\Bridge\Model\ModelMetadataWriter;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataWriter;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Port\CertificateIssuerInterface;
use Beffroi\Saml\Port\IdentityProviderEndpointsInterface;
use Beffroi\Saml\Port\MetadataWriterInterface;
use Beffroi\Saml\Port\ServiceProviderMetadataWriterInterface;
use App\Doctrine\Repository\DoctrineAcceptedMetadataRepository;
use App\Saml\MetadataFetcher;
use Beffroi\Saml\Application\Metadata\MetadataRefresh;
use Beffroi\Saml\Application\ServiceProvider\ServiceProviderRole;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use App\Command\SamlServiceProviderRefreshCommand;
use App\Command\SamlServiceProviderForgetCommand;
use App\MessageHandler\RefreshTheSamlMetadataHandler;
use App\Command\SamlIdentityProviderRefreshCommand;
use App\Command\SamlIdentityProviderForgetCommand;
use App\Saml\WiredProfileClaims;
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
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryHeldKeyJwsVerifier;
use Beffroi\Core\Port\HeldKeyJwsVerifierInterface;
use Beffroi\Core\Port\CheckpointCopiesInterface;
use Beffroi\Core\Port\RelinkableChainsInterface;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodyOpener;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodySealer;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use App\Geo\GeoLite2Databases;
use App\Geo\GeoLite2GeoLocator;
use App\Geo\GeoLite2Refresh;
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
use Beffroi\Core\Bridge\Password\Pbkdf2PasswordHasher;
use Beffroi\Core\Bridge\Password\WiredPasswordAlgorithms;
use Beffroi\Core\Bridge\Session\WiredAuthenticationPredicates;
use Beffroi\Core\Domain\Session\PhishingResistant;
use Beffroi\Core\Domain\Session\PhishingResistantHardware;
use Beffroi\Core\Domain\Session\SingleFactor;
use Beffroi\Core\Domain\Session\TwoFactors;
use Beffroi\Core\Bridge\Webauthn\MetadataBlobVerifier;
use Beffroi\Core\Bridge\Webauthn\PasskeyAlgorithms;
use Beffroi\Core\Bridge\Webauthn\ProviderPasskeyAlgorithms;
use Beffroi\Core\Bridge\Webauthn\MetadataAuthenticatorModels;
use Beffroi\Core\Bridge\Webauthn\StoredAuthenticatorList;
use Beffroi\Core\Bridge\Webauthn\StoredMetadata;
use Beffroi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Beffroi\Core\Bridge\Webauthn\WebauthnPasskeyAuthenticator;
use Beffroi\Core\Bridge\Webauthn\WebauthnPasskeyRegistrar;
use Beffroi\Core\Bridge\Webauthn\WiredPasskeyAttestationPolicies;
use Beffroi\Core\Bridge\Webauthn\PkiAttestationRootReader;
use Beffroi\Core\Application\Passkey\PasskeyAttestations;
use Beffroi\Core\Domain\Credential\Attestation\DirectAttestation;
use Beffroi\Core\Domain\Credential\Attestation\EnterpriseAttestation;
use Beffroi\Core\Domain\Credential\Attestation\NoAttestation;
use Beffroi\Core\Port\AttestationRootReaderInterface;
use Beffroi\Core\Port\PasskeyAttestationPoliciesInterface;
use App\Fido\Conformance\ConformanceToolsRegistrar;
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
use Beffroi\Core\Port\SignedCheckpointsInterface;
use Beffroi\Core\Port\ChainOfRowsInterface;
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
use Beffroi\Core\Port\AuthenticatorListStoreInterface;
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
use Beffroi\Core\Port\SigningKeyOpenerInterface;
use Beffroi\Core\Port\SigningKeyProviderInterface;
use Beffroi\Core\Port\SubjectsOfSessionsInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Port\UserAgentParserInterface;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use Beffroi\Core\Port\AtomicWritesInterface;
use Beffroi\Core\Port\ExclusiveSectionsInterface;
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
use Beffroi\Oidc\Application\Claims\Sector\IdentifiersWithoutARedirection;
use Beffroi\Oidc\Application\Claims\Sector\JwksUriSectorIdentifier;
use Beffroi\Oidc\Application\Claims\Sector\RedirectUriSectorIdentifier;
use Beffroi\Oidc\Application\Claims\Sector\RegisteredSectorIdentifier;
use Beffroi\Oidc\Application\Claims\SectorIdentifiers;
use Beffroi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Beffroi\Oidc\Application\Claims\ServedClaims;
use Beffroi\Oidc\Application\Claims\ClaimsAskedByName;
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
use Beffroi\Oidc\Application\Dpop\DpopChallengeParameters;
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
use Beffroi\Oidc\Application\Consent\SharedIdentity;
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
use Beffroi\Oidc\Application\Token\AdministrationAudienceGuard;
use Beffroi\Oidc\Application\Administration\AdministrationAudience;
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
use Beffroi\Oidc\Bridge\Pki\PkiFrameworkCertificateAuthorities;
use Beffroi\Oidc\Bridge\Pki\PkiFrameworkCertificateReader;
use Beffroi\Oidc\Port\AccessTokenIssuerInterface;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use Beffroi\Oidc\Port\CanPageActiveConsentsInterface;
use Beffroi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Beffroi\Oidc\Port\CanRevokeGrantsByConsentInterface;
use Beffroi\Oidc\Port\RecordedGrantsInterface;
use Beffroi\Oidc\Port\CertificateReaderInterface;
use Beffroi\Oidc\Port\ChallengeParametersInterface;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use Beffroi\Oidc\Port\ClientAssertionReplayGuardInterface;
use Beffroi\Oidc\Port\IssuerAssertionReplayGuardInterface;
use Beffroi\Oidc\Port\SoftwareStatementReplayGuardInterface;
use Beffroi\Oidc\Port\PresentedTokenTypesInterface;
use Beffroi\Oidc\Port\TrustedIssuersInterface;
use Beffroi\Oidc\Port\RequestObjectReplayGuardInterface;
use Beffroi\Oidc\Port\ClientAssertionSecretVerifierInterface;
use Beffroi\Oidc\Port\ClientCertificateAuthoritiesInterface;
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
use Beffroi\Oidc\Application\Client\Registration\RegistrationSignedWithHeldKeys;
use Beffroi\Oidc\Application\Scope\OfferedScopes;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRegistrationPolicy;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationDeclaredScopes;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationAdministrationResource;
use Beffroi\Oidc\Port\AdministrationResourceInterface;
use Beffroi\Oidc\Port\ClientRegistrationPolicyInterface;
use Beffroi\Oidc\Port\ClientRetentionPolicyInterface;
use Beffroi\Oidc\Port\ClientInventoryInterface;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\IssuedInitialAccessTokensInterface;
use Beffroi\Oidc\Port\DeclaredScopesInterface;
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
use Beffroi\Oidc\Port\RefreshTokenRotationInterface;
use Beffroi\Oidc\Port\RequestObjectFetcherInterface;
use Beffroi\Oidc\Port\LogoutTokenDeliveryInterface;
use Beffroi\Oidc\Port\LogoutTokenRetriesInterface;
use Beffroi\Oidc\Port\ServedLogoutChannelsInterface;
use Beffroi\Oidc\Port\ServedResponseModesInterface;
use Beffroi\Oidc\Port\AssignedSubjectTypesInterface;
use Beffroi\Oidc\Port\PairwiseSaltInterface;
use Beffroi\Oidc\Port\PairwiseSubjectRepositoryInterface;
use Beffroi\Oidc\Port\PresentedSubjectReaderInterface;
use Beffroi\Oidc\Port\SectorIdentifierDocumentFetcherInterface;
use Beffroi\Oidc\Port\SectorIdentifiersInterface;
use Beffroi\Oidc\Port\SubjectIdentifierOpenerInterface;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;
use Beffroi\Oidc\Port\UnsignedRequestObjectsInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\HS256;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Bridge\Doctrine\Messenger\DoctrineDbalCloseConnectionMiddleware;
use Symfony\Bridge\Doctrine\Messenger\DoctrineDbalPingConnectionMiddleware;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\RateLimiter\Storage\CacheStorage;
use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\iterator;
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
use App\Configuration\MutualTlsSection;
use App\Configuration\SamlSection;
use App\Configuration\SecretFile;
use App\Configuration\SwitchedServices;
use App\Configuration\WebPushSection;
use App\Security\UpstreamLogin;
use App\Push\WebPushBroadcast;
use App\Push\WebPushSender;
use App\Http\NotificationsPage;
use App\Http\ProviderScript;
use App\Http\Account\NotificationsSection;
use App\Http\Account\SessionsSection;
use App\Http\Account\PasswordSection;
use App\Http\Account\ActsSection;
use App\Doctrine\Repository\DoctrinePushSubscriptionRepository;
use App\Ciba\WebPushApprovalChannel;
use App\Ciba\MailApprovalChannel;
use App\Ciba\SmsApprovalChannel;
use App\Ciba\PendingApprovalWording;
use App\Configuration\MailSection;
use App\Configuration\SmsSection;
use App\Mail\MailSender;
use App\Administration\Controller\MailSigningKeysController;
use App\Key\FileMailSigningKeyRepository;
use App\Mail\Gnupg;
use App\Mail\MailKeyReaders;
use App\Mail\MailProtection;
use App\Mail\MailSenderAddress;
use App\Mail\OpenedMailSigningKeys;
use App\Mail\PgpMailSigner;
use App\Mail\PgpMime;
use App\Mail\PgpSigningKeys;
use App\Mail\Smime;
use App\Mail\SmimeMailSigner;
use App\Mail\SmimeSigningKeys;
use Beffroi\Core\Application\Identity\MailEncryptionChoice;
use Beffroi\Core\Application\Key\MailSigningKeyAdoption;
use Beffroi\Core\Port\MailSigningKeyRepositoryInterface;
use App\Sms\SmsSender;
use App\Notification\NotificationKinds;
use App\Notification\OfferedChannels;
use App\Http\AskedChannels;
use Beffroi\Core\Application\Notification\ChannelChoice;
use Beffroi\Core\Domain\Credential\CredentialChangeKind;
use Beffroi\Oidc\Domain\Ciba\PendingApprovalKind;
use App\Confirmation\AddressConfirmationWording;
use App\Confirmation\MailAddressConfirmationChannel;
use App\Confirmation\QueuedAddressConfirmationSender;
use App\Confirmation\SmsAddressConfirmationChannel;
use App\Confirmation\WiredAddressConfirmations;
use App\Doctrine\Repository\DoctrineEmailConfirmationRepository;
use App\Doctrine\Repository\DoctrinePhoneNumberConfirmationRepository;
use App\MessageHandler\SendAddressConfirmationHandler;
use Beffroi\Core\Application\Confirmation\AddressConfirmationIssuing;
use Beffroi\Core\Application\Confirmation\AddressConfirmationRedeeming;
use Beffroi\Core\Application\Confirmation\AddressEstablishment;
use Beffroi\Core\Domain\Confirmation\ConfirmableEmail;
use Beffroi\Core\Domain\Confirmation\ConfirmablePhoneNumber;
use Beffroi\Core\Port\AddressConfirmationSenderInterface;
use Beffroi\Core\Port\ConfirmationSendLimiterInterface;
use App\Confirmation\RateLimitedConfirmationSends;

return static function (ContainerConfigurator $container): void {
    $services = $container->services();
    $services->defaults()->autowire()->autoconfigure()->private()->bind(EventDispatcherInterface::class, service(EventBusDispatcher::class));

    $services->set(EventBusDispatcher::class)->args([service('event.bus')]);
    $services->set(PlaneRequestListener::class)->args(['%' . Plane::PARAMETER . '%']);
    $services->set(TenantFactory::class);

    $services->load('App\\Controller\\', '../../src/Controller/');
    $services->load('App\\Administration\\', '../../src/Administration/');
    $services->set(AdministrationGuard::class)->arg('$plane', '%' . Plane::PARAMETER . '%');
    $services->get(HealthController::class)->args([
        '$checks' => tagged_iterator('beffroi.doctor_check'),
    ]);
    $services->set(ProtectedResourceRefusals::class);
    $services->load('App\\Form\\', '../../src/Form/');
    $services->set(RequestContextFactory::class);
    $services->set(FapiInteractionId::class);
    $services->set(BrowserSession::class);
    $services->set(DatabaseSessions::class)->args([service('doctrine.dbal.default_connection'), service('beffroi.personal_data.encrypter')]);
    $services->set(InteractionPages::class);
    $services->set(CrossSitePost::class);
    $services->set(CrossSiteSessionCookie::class);
    $services->set(FormTarget::class);
    $services->set(ImageSource::class);
    $services->set(AskedPage::class);
    $services->set(AskedPeriod::class);
    $services->set(AskedWord::class);
    $services->set(PageOfRows::class);
    $services->set(WhatWasRefused::class);
    $services->set(UntoldChange::class);
    $services->set(FormToken::class);
    $services->set(LoginTarget::class);
    $services->set(LoginAddresses::class);
    $services->set(UpstreamDiscovery::class);
    $services->set(UpstreamSignOnReferences::class);
    $services->set(RecentLogin::class);
    $services->set(RecentProofListener::class);
    $services->set(BreachedPasswordDemand::class);
    $services->set(DeviceApprovalPage::class);
    $services->set(PendingApprovalsPage::class);
    $services->set(PushSubscriptionEnrolment::class);
    $services->set(PushSubscriptionNaming::class);
    $services->set(PushSubscriptionRevocation::class);
    $services->set(NotificationsPage::class);
    $services->set(CredentialChangeKind::class)->tag(NotificationKinds::TAG);
    $services->set(PendingApprovalKind::class)->tag(NotificationKinds::TAG);
    $services->set(NotificationKinds::class)->args([tagged_iterator(NotificationKinds::TAG)]);
    // A person chooses among the channels of a pending approval, the one kind whose channels they choose.
    $services->set(OfferedChannels::class)->args([service('beffroi.pending_approval_channels')]);
    $services->set(AskedChannels::class);
    $services->set(ChannelChoice::class);
    $services->set(WebPushSender::class)->tag(ThirdPartyRequestsPass::TAG);
    $services->set(WebPushBroadcast::class);
    $services->set(MailSender::class);
    $services->set(MailSenderAddress::class);
    // The order of the signers is the order a format signs in when the person gave no key of their own (decision 0051).
    $services->set(SmimeMailSigner::class)->tag('beffroi.mail_signer');
    $services->set(PgpMailSigner::class)->tag('beffroi.mail_signer');
    $services->set(Gnupg::class);
    $services->set(Smime::class)->tag('beffroi.mail_key_reader')->tag('beffroi.mail_encrypter');
    $services->set(PgpMime::class)->tag('beffroi.mail_key_reader')->tag('beffroi.mail_encrypter');
    $services->set(MailKeyReaders::class)->args([tagged_iterator('beffroi.mail_key_reader')]);
    $services->set(MailProtection::class)->args([
        '$signers' => tagged_iterator('beffroi.mail_signer'),
        '$encrypters' => tagged_iterator('beffroi.mail_encrypter'),
    ]);
    $services->set(OpenedMailSigningKeys::class)->arg('$signers', tagged_iterator('beffroi.mail_signer'));
    $services->set(SmimeSigningKeys::class);
    $services->set(PgpSigningKeys::class)->arg('$bits', service(RsaKeyBits::class));
    $services->set(FileMailSigningKeyRepository::class);
    $services->alias(MailSigningKeyRepositoryInterface::class, FileMailSigningKeyRepository::class);
    $services->set(MailSigningKeyAdoption::class);
    $services->set(MailEncryptionChoice::class);
    $services->get(MailSigningKeysController::class)->arg('$signers', tagged_iterator('beffroi.mail_signer'));
    $services->set(SmsSender::class);
    $services->set(PendingApprovalWording::class);
    $services->set(WebPushApprovalChannel::class);
    $services->set(MailApprovalChannel::class);
    $services->set(SmsApprovalChannel::class);
    $services->set(CredentialChangeNotices::class)->arg('$router', service(ProviderRoutes::URL_GENERATOR));
    $services->set(WebPushCredentialChangeChannel::class);
    $services->set(MailCredentialChangeChannel::class);
    $services->set(SmsCredentialChangeChannel::class);
    $services->set(MailToTheReplacedAddressChannel::class);
    $services->set(SmsToTheReplacedNumberChannel::class);
    $services->set(AccountAccess::class);
    $services->set(ProviderScript::class);
    // The home of the account shows these sections in the order they are wired.
    $services->set(ApprovalsSection::class)->tag('beffroi.account_section');
    $services->set(ProfileSection::class)->tag('beffroi.account_section');
    $services->set(PasskeysSection::class)->tag('beffroi.account_section');
    $services->set(TwoFactorSection::class)->tag('beffroi.account_section');
    $services->set(ConsentsSection::class)->tag('beffroi.account_section');
    $services->set(SessionsSection::class)->tag('beffroi.account_section');
    $services->set(SessionsPage::class);
    $services->set(ApplicationHoldings::class);
    $services->set(ApplicationPage::class);
    $services->set(PasswordSection::class)->tag('beffroi.account_section');
    $services->set(ActsSection::class)->tag('beffroi.account_section');
    $services->set(ActsPage::class);
    $services->set(NotificationsSection::class)->tag('beffroi.account_section');
    $services->set(ArchiveSection::class)->tag('beffroi.account_section');
    $services->set(AccountSections::class)->args([tagged_iterator('beffroi.account_section')]);
    $services->set(AccountHomePage::class);
    $services->set(ServedLocales::class);
    $services->set(UserLocale::class);
    $services->set(LocalePreference::class)->tag('beffroi.browser_preference');
    $services->set(BrowserPreferences::class)->args([tagged_iterator('beffroi.browser_preference')]);
    $services->set(LocaleExtension::class);
    $services->set(DoctrineJournal::class);
    $services->alias(JournalInterface::class, DoctrineJournal::class);
    $services->alias(ActsOfAPersonInterface::class, DoctrineJournal::class);
    $services->alias(CanPageActsOfAPersonInterface::class, DoctrineJournal::class);
    $services->alias(CanCountActsInterface::class, DoctrineJournal::class);
    $services->set(JournalChain::class)->tag('beffroi.chain');
    $services->set(ClaimHistoryChain::class)->tag('beffroi.chain');
    $services->set(DisclosureChain::class)->tag('beffroi.chain');
    $services->set(JournalTable::class)->tag('beffroi.chained_table');
    $services->set(ClaimHistoryTable::class)->tag('beffroi.chained_table');
    $services->set(DisclosureTable::class)->tag('beffroi.chained_table');
    $services->set(DoctrineChains::class)->arg('$tables', tagged_iterator('beffroi.chained_table'));
    $services->set(RuntimeRoleGrants::class)->arg('$tables', tagged_iterator('beffroi.chained_table'));
    $services->alias(ChainOfRowsInterface::class, DoctrineChains::class);
    $services->alias(RelinkableChainsInterface::class, DoctrineChains::class);
    $services->set(FileChainCheckpoints::class);
    $services->alias(SignedCheckpointsInterface::class, FileChainCheckpoints::class);
    $services->set(LoggedCheckpointCopies::class);
    $services->alias(CheckpointCopiesInterface::class, LoggedCheckpointCopies::class);
    $services->set(ActRecording::class);
    $services->set(PersonKind::class)->tag('beffroi.author_kind');
    $services->set(AdministratorKind::class)->tag('beffroi.author_kind');
    $services->set(ClientKind::class)->tag('beffroi.author_kind');
    $services->set(DirectoryKind::class)->tag('beffroi.author_kind');
    $services->set(UpstreamKind::class)->tag('beffroi.author_kind');
    $services->set(UnauthenticatedKind::class)->tag('beffroi.author_kind');
    $services->set(HostKind::class)->tag('beffroi.author_kind');
    $services->set(Authors::class)->args([tagged_iterator('beffroi.author_kind')]);
    $services->alias(AuthorReaderInterface::class, Authors::class);
    $services->alias(KindsOfAuthorInterface::class, Authors::class);
    $services->alias('beffroi.authors', AuthorReaderInterface::class)->public();
    $services->set(ChainWalk::class);
    $services->set(ChainCheckpoints::class);
    $services->set(ChainSignature::class);
    $services->set(ChainVerification::class);
    $services->set(ChainCut::class);
    $services->set(ChainRelinking::class);
    $services->set(LoggedCut::class);
    $services->set(JournalRetention::class);
    $services->set(DoctrineDisclosures::class);
    $services->alias(DisclosuresInterface::class, DoctrineDisclosures::class);
    $services->alias(DisclosuresOfAPersonInterface::class, DoctrineDisclosures::class);
    $services->set(DisclosureRecording::class);
    $services->set(DisclosureRetention::class);
    // The archive file holds its chapters in the order they are tagged below.
    $services->set(DoctrinePersonalArchiveRepository::class);
    $services->alias(PersonalArchiveRepositoryInterface::class, DoctrinePersonalArchiveRepository::class);
    $services->set(DoctrineGroupMembershipRepository::class);
    $services->alias(GroupsOfAPersonInterface::class, DoctrineGroupMembershipRepository::class);
    $services->alias(GroupMembershipRepositoryInterface::class, DoctrineGroupMembershipRepository::class);
    $services->alias(MembersOfAGroupInterface::class, DoctrineGroupMembershipRepository::class);
    $services->set(DoctrineGroupRepository::class);
    $services->alias(GroupRepositoryInterface::class, DoctrineGroupRepository::class);
    $services->alias(GroupsOfATenantInterface::class, DoctrineGroupRepository::class);
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
    $services->set(ZipArchiveContainer::class);
    $services->alias(ArchiveContainerInterface::class, ZipArchiveContainer::class);
    $services->set(ArchivePage::class)->args([
        '$chapters' => tagged_iterator('beffroi.archive_chapter'),
    ]);
    // The profile page offers the claims in the order they are wired.
    $services->set(Name::class)->tag('beffroi.claim');
    $services->set(GivenName::class)->tag('beffroi.claim');
    $services->set(FamilyName::class)->tag('beffroi.claim');
    $services->set(MiddleName::class)->tag('beffroi.claim');
    $services->set(Nickname::class)->tag('beffroi.claim');
    $services->set(PreferredUsername::class)->tag('beffroi.claim');
    $services->set(Birthdate::class)->tag('beffroi.claim');
    $services->set(Gender::class)->tag('beffroi.claim');
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
    $services->alias(ClaimsInterface::class, WiredClaims::class);
    $services->set(SelfDescription::class);
    // An administrator says the members of a person beside their claims in the order they are wired: an address before
    // whether it was verified.
    $services->set(UsernameMember::class)->tag('beffroi.person_member');
    $services->set(EmailMember::class)->tag('beffroi.person_member');
    $services->set(EmailVerifiedMember::class)->tag('beffroi.person_member');
    $services->set(PhoneNumberVerifiedMember::class)->tag('beffroi.person_member');
    $services->set(AddressMember::class)->tag('beffroi.person_member');
    $services->set(PersonDescription::class)->arg('$members', tagged_iterator('beffroi.person_member'));
    $services->set(DoctrineClaimHistory::class);
    $services->alias(ClaimHistoryInterface::class, DoctrineClaimHistory::class);
    $services->alias(ChangesOfAPersonInterface::class, DoctrineClaimHistory::class);
    $services->alias(CanPageChangesOfAPersonInterface::class, DoctrineClaimHistory::class);
    $services->set(ClaimHistoryRetention::class);
    $services->set(LanguageRecording::class);
    $services->set(UserTimeZone::class);
    $services->set(Moments::class);
    $services->set(MomentExtension::class);
    $services->set(ClientNameExtension::class);
    $services->set(PlaceExtension::class);
    $services->set(AuthorExtension::class);
    $services->set(DeviceExtension::class);
    $services->set(AuthenticatorModelExtension::class);
    $services->set(TenantExtension::class);
    $services->set(InteractionLocale::class)->args([
        '$tenants' => service(AmbientTenantInterface::class),
    ]);
    $services->set(QueryResponseRenderer::class)->tag('beffroi.response_mode');
    $services->set(FormPostResponseRenderer::class)->tag('beffroi.response_mode');
    $services->set(SignedQueryResponseRenderer::class)->tag('beffroi.response_mode');
    $services->set(SignedFormPostResponseRenderer::class)->tag('beffroi.response_mode');
    $services->set(AuthorizationResponseRenderers::class)->args([tagged_iterator('beffroi.response_mode')]);
    $services->alias(ServedResponseModesInterface::class, AuthorizationResponseRenderers::class);

    $services->set(InteractionPage::class);
    $services->set(LoginRequiredRenderer::class)->tag('beffroi.authorization_decision');
    $services->set(ConsentRequiredRenderer::class)->tag('beffroi.authorization_decision');
    $services->set(GrantedRenderer::class)->tag('beffroi.authorization_decision');
    $services->set(DecisionRenderers::class)->args([tagged_iterator('beffroi.authorization_decision')]);
    $services->set(AuthorizationResponder::class);
    $services->alias(AuthorizationResponderInterface::class, AuthorizationResponder::class);
    $services->set(AuthorizationRequestReader::class);
    $services->alias(AuthorizationRequestReaderInterface::class, AuthorizationRequestReader::class);
    $services->set(PasskeyOptionsStore::class);
    $services->set(ProfilePage::class);
    $services->set(ClaimChangesPage::class);
    $services->set(PasskeysPage::class);
    $services->set(PasswordPage::class);
    $services->set(ConsentsPage::class);
    $services->set(PendingLoginStore::class);
    $services->set(TotpProvisioningSealer::class)->arg('$sealer', service(KeysSection::TOTP_PROVISIONING_SEALER));
    $services->set(TotpProvisioningStore::class);
    $services->set(QrCode::class);
    $services->set(TwoFactorPage::class);
    $services->set(TotpSecretShown::class);
    $services->set(RouterEndpointLocator::class)->arg('$router', service(ProviderRoutes::URL_GENERATOR));
    $services->alias(EndpointLocatorInterface::class, RouterEndpointLocator::class);
    $services->alias(MutualTlsEndpointLocatorInterface::class, RouterEndpointLocator::class);
    $services->alias(ClientConfigurationEndpointInterface::class, RouterEndpointLocator::class);
    // The certificate is never read from a header: a deployment behind another proxy replaces this implementation.
    $services->set(EdgeClientCertificateResolver::class);
    $services->alias(ClientCertificateResolverInterface::class, EdgeClientCertificateResolver::class);
    $services->set(PresentedClientCertificate::class);

    $services->load('App\\Command\\', '../../src/Command/');
    $services->get(DoctorCommand::class)->args([
        '$checks' => tagged_iterator('beffroi.doctor_check'),
    ]);
    $services->set(LaneBacklogs::class)->args([service('messenger.receiver_locator')]);
    $services->set(InstanceStatistics::class);
    $services->set(ClientsSignedWithHeldKeys::class)->arg('$sources', tagged_iterator('beffroi.oidc.client_source'))->tag('beffroi.doctor_check');
    foreach ([JournalChain::class, ClaimHistoryChain::class, DisclosureChain::class] as $chain) {
        $services->set('beffroi.doctor.chain.' . $chain, ChainHoldsTogether::class)->arg('$chain', service($chain))->tag('beffroi.doctor_check');
    }
    $services->set(NamedChain::class)->arg('$chains', tagged_iterator('beffroi.chain'));
    $services
        ->set(NotificationsLanePatience::class)
        ->args([
            service('messenger.senders_locator'),
            service('messenger.retry_strategy_locator'),
            service(NotificationRetryPolicy::class),
            service(LogoutTokenDeliveryInterface::class),
        ])
        ->tag('beffroi.doctor_check');

    // Wired in every environment, reached only through config/beffroi/routes/fido-conformance.php, which the
    // application imports in development only.
    $services->set('beffroi.fido_conformance.ceremonies', WebauthnCeremonies::class)->arg('$algorithms', service(ConformanceToolsAlgorithms::class));
    $services->set('beffroi.fido_conformance.options', WebauthnPasskeyRegistrar::class)->arg('$ceremonies', service('beffroi.fido_conformance.ceremonies'));
    $services->set('beffroi.fido_conformance.registrar', ConformanceToolsRegistrar::class)->args([
        '$drawn' => service('beffroi.fido_conformance.options'),
        '$ceremonies' => service('beffroi.fido_conformance.ceremonies'),
    ]);
    $services->set('beffroi.fido_conformance.authenticator', WebauthnPasskeyAuthenticator::class)->arg(
        '$ceremonies',
        service('beffroi.fido_conformance.ceremonies'),
    );
    $services->set('beffroi.fido_conformance.enrolment', PasskeyEnrolment::class)->arg('$registrar', service('beffroi.fido_conformance.registrar'));
    $services->set('beffroi.fido_conformance.authentication', PasskeyAuthentication::class)->arg(
        '$authenticator',
        service('beffroi.fido_conformance.authenticator'),
    );
    $services
        ->load('App\\Fido\\Conformance\\', '../../src/Fido/Conformance/')
        ->bind(WebauthnCeremonies::class . ' $ceremonies', service('beffroi.fido_conformance.ceremonies'))
        ->bind(PasskeyEnrolment::class . ' $enrolment', service('beffroi.fido_conformance.enrolment'))
        ->bind(PasskeyAuthentication::class . ' $authentication', service('beffroi.fido_conformance.authentication'));
    // Wired in every environment, reached only through config/beffroi/routes/ciba-conformance.php, which the
    // application imports in development only.
    $services->load('App\\Ciba\\Conformance\\', '../../src/Ciba/Conformance/');

    $services->load('App\\MessageHandler\\', '../../src/MessageHandler/');
    $services->get(SignTheChainsHandler::class)->arg('$chains', tagged_iterator('beffroi.chain'));
    $services->get(QueueLogoutTokenHandler::class)->tag('beffroi.logout_channel');
    $services->set(BeffroiSchedule::class);
    // WebPushSection::CHANNEL_TAG is for a deployment's own channels; the provider tags none.
    $services->set(QueuedPendingApprovalNotifier::class);
    $services->alias(PendingApprovalNotifierInterface::class, QueuedPendingApprovalNotifier::class);
    // The channels of the deployment, then web push, mail and SMS, each while its role is on, mail and SMS each with the
    // channel that reaches the address or the number a change replaced.
    $services->set('beffroi.pending_approval_channels', SwitchedServices::class)->args([
        inline_service(SwitchedServices::class)->args([
            inline_service(SwitchedServices::class)->args([
                tagged_iterator(WebPushSection::CHANNEL_TAG),
                service(WebPushSection::ROLE),
                iterator([service(WebPushApprovalChannel::class)]),
            ]),
            service(MailSection::ROLE),
            iterator([service(MailApprovalChannel::class)]),
        ]),
        service(SmsSection::ROLE),
        iterator([service(SmsApprovalChannel::class)]),
    ]);
    $services->get(TellUserOfPendingApprovalHandler::class)->args([
        '$channels' => service('beffroi.pending_approval_channels'),
    ]);
    // WebPushSection::CREDENTIAL_CHANGE_CHANNEL_TAG is for a deployment's own channels; the provider tags none.
    // The channels of the deployment, then web push, mail and SMS, each while its role is on, mail and SMS each with the
    // channel that reaches the address or the number a change replaced.
    $services->set(CredentialChangeChannels::class)->args([
        inline_service(SwitchedServices::class)->args([
            inline_service(SwitchedServices::class)->args([
                inline_service(SwitchedServices::class)->args([
                    tagged_iterator(WebPushSection::CREDENTIAL_CHANGE_CHANNEL_TAG),
                    service(WebPushSection::ROLE),
                    iterator([service(WebPushCredentialChangeChannel::class)]),
                ]),
                service(MailSection::ROLE),
                iterator([service(MailCredentialChangeChannel::class), service(MailToTheReplacedAddressChannel::class)]),
            ]),
            service(SmsSection::ROLE),
            iterator([service(SmsCredentialChangeChannel::class), service(SmsToTheReplacedNumberChannel::class)]),
        ]),
    ]);
    $services->set(QueuedCredentialChangeNotifier::class);
    $services->alias(CredentialChangeNotifierInterface::class, QueuedCredentialChangeNotifier::class);
    $services->set(RateLimitedChannelChangeWindow::class)->args([service('limiter.' . RateLimitedChannelChangeWindow::LIMITER)]);
    $services->alias(ChannelChangeWindowInterface::class, RateLimitedChannelChangeWindow::class);
    $services->set(ChannelChangeNotice::class);
    // An address is established by the code and the link sent there (NIST SP 800-63B-4 §4.2.1.2): each kind while the
    // channel that reaches it is on, the email address by mail and the phone number by SMS.
    $services->set(DoctrineEmailConfirmationRepository::class)->tag('beffroi.dead_records');
    $services->set(DoctrinePhoneNumberConfirmationRepository::class)->tag('beffroi.dead_records');
    $services->set(ConfirmableEmail::class);
    $services->set(ConfirmablePhoneNumber::class);
    $services->set(AddressConfirmationIssuing::class);
    $services->set(AddressConfirmationRedeeming::class);
    $services->set(QueuedAddressConfirmationSender::class);
    $services->alias(AddressConfirmationSenderInterface::class, QueuedAddressConfirmationSender::class);
    // The limits and the interval are filled in by ConfirmationSection; the store and the lock are those of the attempts.
    $services->set(RateLimitedConfirmationSends::class)->args([
        '$storage' => inline_service(CacheStorage::class)->args([service('cache.rate_limiter')]),
        '$locks' => service('lock.factory'),
        '$secret' => '%kernel.secret%',
    ]);
    $services->alias(ConfirmationSendLimiterInterface::class, RateLimitedConfirmationSends::class);
    $services->set('beffroi.address_establishment.email', AddressEstablishment::class)->args([
        '$kind' => service(ConfirmableEmail::class),
        '$confirmations' => service(DoctrineEmailConfirmationRepository::class),
    ]);
    $services->set('beffroi.address_establishment.phone_number', AddressEstablishment::class)->args([
        '$kind' => service(ConfirmablePhoneNumber::class),
        '$confirmations' => service(DoctrinePhoneNumberConfirmationRepository::class),
    ]);
    $services->set(WiredAddressConfirmations::class)->args([
        inline_service(SwitchedServices::class)->args([
            inline_service(SwitchedServices::class)->args([
                [],
                service(MailSection::ROLE),
                iterator([service('beffroi.address_establishment.email')]),
            ]),
            service(SmsSection::ROLE),
            iterator([service('beffroi.address_establishment.phone_number')]),
        ]),
    ]);
    $services->set(AddressConfirmationWording::class)->arg('$router', service(ProviderRoutes::URL_GENERATOR));
    $services->set(MailAddressConfirmationChannel::class)->arg('$kind', service(ConfirmableEmail::class));
    $services->set(SmsAddressConfirmationChannel::class)->arg('$kind', service(ConfirmablePhoneNumber::class));
    $services->get(SendAddressConfirmationHandler::class)->args([
        '$channels' => inline_service(SwitchedServices::class)->args([
            inline_service(SwitchedServices::class)->args([
                [],
                service(MailSection::ROLE),
                iterator([service(MailAddressConfirmationChannel::class)]),
            ]),
            service(SmsSection::ROLE),
            iterator([service(SmsAddressConfirmationChannel::class)]),
        ]),
    ]);
    $services->set(LogoutTokenSender::class)->tag(ThirdPartyRequestsPass::TAG);
    $services->set(ClientNotificationSender::class)->tag(ThirdPartyRequestsPass::TAG);
    $services->set(GivenUpListener::class);
    $services->set(KeysOpenedAtWorkerStart::class)->args([service(KeysOpenedAtStart::BY_THE_CONSUMER)]);
    $services->set(NotificationRetryPolicy::class);
    $services->set(LaneDsn::class);
    $services->set(SecretFile::class);
    $services->set(MessengerContract::SERIALIZER, SealedBodySerializer::class)->args([
        service(TenantProvider::class),
        service(MessageBodySealerInterface::class),
        service(MessageBodyOpenerInterface::class),
    ]);
    $services->set(MessengerContract::PING_CONNECTION, DoctrineDbalPingConnectionMiddleware::class)->args([service('doctrine')]);
    $services->set(MessengerContract::CLOSE_CONNECTION, DoctrineDbalCloseConnectionMiddleware::class)->args([service('doctrine')]);

    $services->set(IdentityUserProvider::class);
    $services->set(CorePasswordHasher::class);
    $services->set(UserChecker::class);
    $services->set(InteractionLoginHandler::class);
    $services->set(LoginSuccessListener::class)->args(['$logins' => tagged_iterator('beffroi.login.dated')]);
    $services->set(LoginFailureListener::class)->args([
        '$logins' => inline_service(SwitchedServices::class)->args([
            tagged_iterator('beffroi.login.refusal'),
            service(SamlSection::SERVICE_PROVIDER_ROLE),
            iterator([service(UpstreamLogin::class)]),
        ]),
    ]);
    $services->set(LoginFormToken::class);
    $services->set(PasswordLoginAuthenticator::class);
    $services->set(PasskeyLoginAuthenticator::class);
    $services->set(SecondFactorGate::class);
    $services->set(TotpLoginAuthenticator::class);
    $services->set(UpstreamAssertionAuthenticator::class);
    // The core announces the refusals of the password and the code and dates what they prove, so their logins
    // carry no "refusal" or "dated" tag.
    $services->set(PasswordLogin::class)->tag('beffroi.login')->tag('beffroi.login.offered');
    $services->set(PasskeyLogin::class)->tag('beffroi.login')->tag('beffroi.login.refusal')->tag('beffroi.login.dated')->tag('beffroi.login.offered');
    $services->set(TotpLogin::class)->tag('beffroi.login');
    $services->set(UpstreamLogin::class);
    $services->set(PassportProofs::class)->args([
        inline_service(SwitchedServices::class)->args([
            tagged_iterator('beffroi.login'),
            service(SamlSection::SERVICE_PROVIDER_ROLE),
            iterator([service(UpstreamLogin::class)]),
        ]),
    ]);
    $services->set(OfferedLogins::class)->args([tagged_iterator('beffroi.login.offered')]);
    $services->alias(ProvableMethodsInterface::class, PassportProofs::class);
    $services->set('beffroi.security.code_attempts', RateLimitedAttempts::class)->args([service('limiter.' . RateLimitedAttempts::CODE_LIMITER)]);
    $services->alias(CodeAttemptLimiterInterface::class, 'beffroi.security.code_attempts');
    $services->set('beffroi.security.password_attempts', RateLimitedAttempts::class)->args([service('limiter.' . RateLimitedAttempts::PASSWORD_LIMITER)]);
    $services->alias(PasswordAttemptLimiterInterface::class, 'beffroi.security.password_attempts');
    $services->set('beffroi.security.password_change_attempts', RateLimitedAttempts::class)->args([
        service('limiter.' . RateLimitedAttempts::PASSWORD_CHANGE_LIMITER),
    ]);
    // PasswordsSection fills the endpoint in; a deployment that names none asks nobody.
    $services->set(PwnedPasswords::class)->args([
        '$endpoint' => '',
    ]);
    $services->alias(BreachedPasswordsInterface::class, PwnedPasswords::class);
    $services->set(BreachedPasswordListener::class);
    $services->set(KmsUnavailableListener::class);

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

    $services->set(EntityManagers::class);
    $services->set(TenantProvider::class)->tag('kernel.reset', [
        'method' => 'reset',
    ])->tag('doctrine.event_listener', [
        'event' => 'onClear',
    ]);
    $services->alias(AmbientTenantInterface::class, TenantProvider::class);
    $services->set(TenantSynchronizer::class);
    $services->set(ClientResolver::class)->tag('doctrine.orm.entity_listener');
    $services->set(DoctrineUserRepository::class);
    $services->alias(UserRepositoryInterface::class, DoctrineUserRepository::class);
    $services->alias(CanCountUsersInterface::class, DoctrineUserRepository::class);
    $services->set(DoctrineAtomicWrites::class);
    $services->alias(AtomicWritesInterface::class, DoctrineAtomicWrites::class);
    $services->set(LockedSections::class)->args([service('lock.factory')]);
    $services->alias(ExclusiveSectionsInterface::class, LockedSections::class);
    $services->set(DoctrineLinkedIdentityRepository::class);
    $services->alias(LinkedIdentityRepositoryInterface::class, DoctrineLinkedIdentityRepository::class);
    $services->set(DoctrinePushSubscriptionRepository::class);
    $services->alias(PushSubscriptionRepositoryInterface::class, DoctrinePushSubscriptionRepository::class);
    $services->alias(CanPageActiveSubscriptionsInterface::class, DoctrinePushSubscriptionRepository::class);
    $services->set(DoctrineCredentialRepository::class);
    $services->alias(CredentialRepositoryInterface::class, DoctrineCredentialRepository::class);
    $services->alias(CanPageCredentialsInterface::class, DoctrineCredentialRepository::class);
    $services->alias(CanForgetCredentialsInterface::class, DoctrineCredentialRepository::class);
    $services->set(ConditionalCredentialWrite::class);
    $services->set(DoctrineTotpUses::class);
    $services->alias(TotpUsesInterface::class, DoctrineTotpUses::class);
    $services->set(DoctrinePasskeyUses::class);
    $services->alias(PasskeyUsesInterface::class, DoctrinePasskeyUses::class);
    $services->set(DoctrineEnrolmentTicketRepository::class)->tag('beffroi.dead_records');
    $services->alias(EnrolmentTicketRepositoryInterface::class, DoctrineEnrolmentTicketRepository::class);
    $services->set(DoctrinePasswordTicketRepository::class)->tag('beffroi.dead_records');
    $services->alias(PasswordTicketRepositoryInterface::class, DoctrinePasswordTicketRepository::class);
    $services->set(DoctrineTotpTicketRepository::class)->tag('beffroi.dead_records');
    $services->alias(TotpTicketRepositoryInterface::class, DoctrineTotpTicketRepository::class);
    $services->set(DoctrineTenantRepository::class);
    $services->alias(TenantRepositoryInterface::class, DoctrineTenantRepository::class);
    $services->set(BoundedDelete::class);
    $services->set(WhatATokenStillNeeds::class);
    $services->set(DeadRecordRemoval::class)->args([tagged_iterator('beffroi.dead_records')]);

    // Asked last, so the rows naming a session are dropped and counted by their own stores, not by the cascade.
    $services->set(DoctrineAuthenticationSessionRepository::class)->tag('beffroi.dead_records', [
        'priority' => -100,
    ]);
    $services->alias(AuthenticationSessionRepositoryInterface::class, DoctrineAuthenticationSessionRepository::class);
    $services->alias(CanFindUnendedSessionsInterface::class, DoctrineAuthenticationSessionRepository::class);
    $services->alias(CanCountActiveSessionsInterface::class, DoctrineAuthenticationSessionRepository::class);
    $services->alias(CanPageActiveSessionsInterface::class, DoctrineAuthenticationSessionRepository::class);
    $services->alias(SubjectsOfSessionsInterface::class, DoctrineAuthenticationSessionRepository::class);
    $services->set(DoctrineInteractionRepository::class)->tag('beffroi.dead_records');
    $services->alias(InteractionRepositoryInterface::class, DoctrineInteractionRepository::class);
    $services->set(DoctrineAuthorizationCodeRepository::class)->tag('beffroi.oidc.grant_record')->tag('beffroi.dead_records');
    $services->alias(AuthorizationCodeRepositoryInterface::class, DoctrineAuthorizationCodeRepository::class);
    $services->alias(LoggedInClientsInterface::class, DoctrineAuthorizationCodeRepository::class);
    $services->set(DoctrinePushedAuthorizationRecordRepository::class)->tag('beffroi.dead_records');
    $services->alias(PushedAuthorizationRecordRepositoryInterface::class, DoctrinePushedAuthorizationRecordRepository::class);
    $services->set(DoctrineDeviceAuthorizationRecordRepository::class)->tag('beffroi.oidc.grant_record')->tag('beffroi.dead_records');
    $services->alias(DeviceAuthorizationRecordRepositoryInterface::class, DoctrineDeviceAuthorizationRecordRepository::class);
    $services->set(DoctrineBackchannelAuthenticationRecordRepository::class)->tag('beffroi.oidc.grant_record')->tag('beffroi.dead_records');
    $services->alias(BackchannelAuthenticationRecordRepositoryInterface::class, DoctrineBackchannelAuthenticationRecordRepository::class);
    $services->set(DoctrineRefreshTokenRepository::class)->tag('beffroi.dead_records');
    $services->alias(RefreshTokenRepositoryInterface::class, DoctrineRefreshTokenRepository::class);
    $services->alias(RefreshTokenRotationInterface::class, DoctrineRefreshTokenRepository::class);
    $services->alias(RefreshTokensOfAConsentInterface::class, DoctrineRefreshTokenRepository::class);
    $services->set(DoctrineAccessTokenRepository::class)->tag('beffroi.dead_records');
    $services->alias(AccessTokenRepositoryInterface::class, DoctrineAccessTokenRepository::class);
    $services->alias(CanRevokeAccessTokensByConsentInterface::class, DoctrineAccessTokenRepository::class);
    $services->alias(CanRevokeAccessTokensBySessionInterface::class, DoctrineAccessTokenRepository::class);
    $services->set(DoctrineConsentRepository::class);
    $services->alias(ConsentRepositoryInterface::class, DoctrineConsentRepository::class);
    $services->alias(ActiveConsentsInterface::class, DoctrineConsentRepository::class);
    $services->alias(CanPageActiveConsentsInterface::class, DoctrineConsentRepository::class);

    $services->set(EnvelopeKeySealer::class);
    $services->alias(KeySealerInterface::class, EnvelopeKeySealer::class);
    $services->set(EnvelopeSecretSealer::class);
    $services->alias(SecretSealerInterface::class, EnvelopeSecretSealer::class);
    $services->set(FileTenantKeyRepository::class);
    $services->alias(TenantKeyRepositoryInterface::class, FileTenantKeyRepository::class);
    $services->set(OpenedKeys::class);
    $services->set(SealedKeyProvider::class);
    $services->alias(SigningKeyProviderInterface::class, SealedKeyProvider::class);
    $services->alias(DecryptionKeyProviderInterface::class, SealedKeyProvider::class);
    $services->alias(PublicKeySetProviderInterface::class, SealedKeyProvider::class);
    $services->alias(ApplicationServerKeyProviderInterface::class, SealedKeyProvider::class);
    $services->alias(KeptSigningKeyProviderInterface::class, SealedKeyProvider::class);
    $services->alias(KeptDecryptionKeyProviderInterface::class, SealedKeyProvider::class);
    $services->alias(MessageKeyProviderInterface::class, SealedKeyProvider::class);
    $services->set(ActiveSigningKeys::class);
    $services->set(HeldSigningAlgorithms::class);
    $services->set(PublishedDecryptionKeys::class);
    $services->set(ActiveKeptSigningKeys::class)->arg('$algorithms', service('beffroi.saml.signing_algorithms'));
    $services->set(KeptDecryptionKeysInService::class);
    $services->set(MessageKeysInService::class);
    $services->set(ApplicationServerKeysInService::class);
    // What each process serves with, and nothing more: a thread never opens a message body, the consumer never a JWE.
    $services
        ->set(KeysOpenedAtStart::BY_A_THREAD, KeysOpenedAtStart::class)
        ->public()
        ->args([
            '$keys' => iterator([
                service(ActiveSigningKeys::class),
                service(PublishedDecryptionKeys::class),
                service(ActiveKeptSigningKeys::class),
                service(KeptDecryptionKeysInService::class),
                service(DataKeysOfTheTenant::class),
            ]),
        ]);
    $services->set(KeysOpenedAtStart::BY_THE_CONSUMER, KeysOpenedAtStart::class)->args([
        '$keys' => iterator([
            service(MessageKeysInService::class),
            service(ActiveSigningKeys::class),
            service(ApplicationServerKeysInService::class),
            service(OpenedMailSigningKeys::class),
            service(DataKeysOfTheTenant::class),
        ]),
    ]);
    // The first one tagged is the default; RS256 stays because OIDC Core §15.1 makes it mandatory.
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
    $services->set(Vapid::class)->tag(DormantKeyAlgorithms::TAG);
    $services->set(JoseApplicationServerAlgorithms::class)->args([
        inline_service(SwitchedServices::class)->args([
            tagged_iterator(WebPushSection::ALGORITHM_TAG),
            service(WebPushSection::ROLE),
            iterator([service(Vapid::class)]),
        ]),
    ]);
    $services->alias(ApplicationServerAlgorithmsInterface::class, JoseApplicationServerAlgorithms::class);
    // Instances of their own: sealing must not depend on a deployment keeping the encryption algorithms above.
    $services
        ->set(MessageSeal::class)
        ->args([inline_service(EcdhEsA256Kw::class), inline_service(A256Gcm::class)])
        ->tag('beffroi.message_sealing_algorithm');
    $services->set(JoseMessageSealingAlgorithms::class)->args([tagged_iterator('beffroi.message_sealing_algorithm')]);
    $services->alias(MessageSealingAlgorithmsInterface::class, JoseMessageSealingAlgorithms::class);
    $services
        ->set(SamlSigning::class)
        ->args([service(RsaKeyBits::class)])
        ->tag(DormantKeyAlgorithms::TAG);
    $services->set('beffroi.saml.signing_algorithms', SwitchedServices::class)->args([
        tagged_iterator(JoseSamlSigningAlgorithms::TAG),
        service(SamlSection::ROLE),
        iterator([service(SamlSigning::class)]),
    ]);
    $services->set(JoseSamlSigningAlgorithms::class)->args([service('beffroi.saml.signing_algorithms')]);
    $services->set(JoseSamlEncryptionAlgorithms::class)->arg('$tagged', tagged_iterator(JoseSamlEncryptionAlgorithms::TAG));
    $services->set(JwtLibraryMessageBodySealer::class);
    $services->alias(MessageBodySealerInterface::class, JwtLibraryMessageBodySealer::class);
    $services->set(JwtLibraryMessageBodyOpener::class);
    $services->alias(MessageBodyOpenerInterface::class, JwtLibraryMessageBodyOpener::class);
    // The registry lists the families, and reads their refusals, in this order.
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
    $services->set(DormantKeyAlgorithms::class)->args([
        tagged_iterator(DormantKeyAlgorithms::TAG),
        [SamlEncryptionAlgorithmInterface::NAME_PREFIX],
    ]);
    $services->set(JwtLibraryKeyPairGenerator::class);
    $services->alias(KeyPairGeneratorInterface::class, JwtLibraryKeyPairGenerator::class);
    $services->set(JwtLibraryJwsSigner::class);
    $services->alias(JwsSignerInterface::class, JwtLibraryJwsSigner::class);
    $services->alias(SigningKeyOpenerInterface::class, JwtLibraryJwsSigner::class);
    $services->set(JwtLibraryJwsVerifier::class);
    $services->alias(JwsVerifierInterface::class, JwtLibraryJwsVerifier::class);
    $services->set(JwtLibraryHeldKeyJwsVerifier::class);
    $services->alias(HeldKeyJwsVerifierInterface::class, JwtLibraryHeldKeyJwsVerifier::class);
    $services->set(JwtLibraryJweDecrypter::class);
    $services->alias(JweDecrypterInterface::class, JwtLibraryJweDecrypter::class);
    $services->set(RetirementWindow::class)->args([
        '$artifacts' => tagged_iterator('beffroi.key_bound_artifact'),
    ]);
    $services->set(NamedKey::class);
    $services->set(KeyStaging::class);
    $services->set(KeyRetirement::class)->args([
        '$holds' => tagged_iterator('beffroi.retirement_hold'),
    ]);
    $services->set(FailedMessagesSealedTo::class)->tag('beffroi.retirement_hold');
    $services->set(KeyTakeOver::class);
    $services->set(KeySuccession::class);

    // Strongest first: the default policy of the core answers in the order they are wired.
    $services->set(PhishingResistantHardware::class)->tag('beffroi.authentication_predicate');
    $services->set(PhishingResistant::class)->tag('beffroi.authentication_predicate');
    $services->set(TwoFactors::class)->tag('beffroi.authentication_predicate');
    $services->set(SingleFactor::class)->tag('beffroi.authentication_predicate');
    $services->set(WiredAuthenticationPredicates::class)->args([tagged_iterator('beffroi.authentication_predicate')]);
    $services->alias(AuthenticationPredicatesInterface::class, WiredAuthenticationPredicates::class);
    // Public: a DBAL type cannot be injected into, so BeffroiKernelTrait::boot() hands it this service.
    $services->alias('beffroi.authentication_predicates', AuthenticationPredicatesInterface::class)->public();

    // The first one is what a new hash is made with; the others are what an import may bring.
    $services->set(Argon2id::class)->tag('beffroi.password_algorithm');
    $services->set(Argon2i::class)->tag('beffroi.password_algorithm');
    $services->set(Bcrypt::class)->tag('beffroi.password_algorithm');
    $services->set(Pbkdf2Sha256::class)->tag('beffroi.password_algorithm');
    $services->set(Pbkdf2Sha512::class)->tag('beffroi.password_algorithm');
    $services->set(WiredPasswordAlgorithms::class)->args([tagged_iterator('beffroi.password_algorithm')]);
    $services->alias(PasswordAlgorithmsInterface::class, WiredPasswordAlgorithms::class);
    // Public: a DBAL type cannot be injected into, so BeffroiKernelTrait::boot() hands it this service.
    $services->alias('beffroi.password_algorithms', PasswordAlgorithmsInterface::class)->public();

    $services->set(NativePasswordHasher::class)->tag('beffroi.password_hasher');
    $services
        ->set(Pbkdf2PasswordHasher::class)
        ->args([service(NativePasswordHasher::class)])
        ->tag('beffroi.password_hasher');
    $services->set(PasswordHasherRegistry::class)->args([tagged_iterator('beffroi.password_hasher'), service(PasswordAlgorithmsInterface::class)]);
    $services->alias(PasswordHasherInterface::class, PasswordHasherRegistry::class);
    $services->set(DecoyHash::class);

    $services->set(FileMetadataBlobStore::class);
    $services->alias(MetadataBlobStoreInterface::class, FileMetadataBlobStore::class);
    $services->set(DocumentDownload::class);
    $services->set(StoredMetadata::class);
    $services->alias(MetadataStatementRepository::class, StoredMetadata::class);
    $services->alias(StatusReportRepository::class, StoredMetadata::class);
    $services->set(RevocationListClient::class);
    $services->set(PhpCertificateChainValidator::class)->arg('$client', service(RevocationListClient::class));
    $services->alias(CertificateChainValidator::class, PhpCertificateChainValidator::class);
    $services->set(MetadataBlobVerifier::class);
    $services->set(NoAttestation::class)->tag('beffroi.passkey_attestation_policy');
    $services->set(DirectAttestation::class)->tag('beffroi.passkey_attestation_policy');
    $services->set(EnterpriseAttestation::class)->tag('beffroi.passkey_attestation_policy');
    $services->set(WiredPasskeyAttestationPolicies::class)->args([tagged_iterator('beffroi.passkey_attestation_policy')]);
    $services->alias(PasskeyAttestationPoliciesInterface::class, WiredPasskeyAttestationPolicies::class);
    $services->set(PkiAttestationRootReader::class);
    $services->alias(AttestationRootReaderInterface::class, PkiAttestationRootReader::class);
    $services->set(PasskeyAttestations::class);
    // Public: a DBAL type cannot be injected into, so BeffroiKernelTrait::boot() hands it this service.
    $services->alias('beffroi.passkey_attestations', PasskeyAttestations::class)->public();
    $services->set(ProviderPasskeyAlgorithms::class);
    $services->alias(PasskeyAlgorithms::class, ProviderPasskeyAlgorithms::class);
    $services->set(WebauthnCeremonies::class);
    $services->set(WebauthnPasskeyRegistrar::class);
    $services->alias(PasskeyRegistrarInterface::class, WebauthnPasskeyRegistrar::class);
    $services->set(WebauthnPasskeyAuthenticator::class);
    $services->alias(PasskeyAuthenticatorInterface::class, WebauthnPasskeyAuthenticator::class);
    // The FIDO metadata first, so that a name the FIDO Alliance signed is never replaced by one nobody signed.
    $services->set(MetadataAuthenticatorModels::class);
    $services->set(FileAuthenticatorListStore::class);
    $services->alias(AuthenticatorListStoreInterface::class, FileAuthenticatorListStore::class);
    $services->set(StoredAuthenticatorList::class);
    $services->set(AuthenticatorModels::class)->args([[
        service(MetadataAuthenticatorModels::class),
        service(StoredAuthenticatorList::class),
    ]]);

    $services->set(OtphpTotpAlgorithm::class);
    $services->alias(TotpAlgorithmInterface::class, OtphpTotpAlgorithm::class);
    $services->set(TotpCodeMatcher::class);
    $services->set(ActiveTotp::class);

    $services->set(GeoLite2Databases::class);
    $services->set(GeoLite2Refresh::class);
    $services->set(GeoLite2GeoLocator::class);
    $services->alias(GeoLocatorInterface::class, GeoLite2GeoLocator::class);
    $services->set(ProvenancePlace::class);
    $services->set(SessionProvenanceEnrichment::class);
    $services->set(NullUserAgentParser::class);
    $services->alias(UserAgentParserInterface::class, NullUserAgentParser::class);

    $services->set(SymfonyUuidGenerator::class);
    $services->alias(UuidGeneratorInterface::class, SymfonyUuidGenerator::class);
    $services->set(PlatformRandomness::class);
    $services->alias(RandomnessInterface::class, PlatformRandomness::class);
    $services->set(PlatformMonotonicClock::class);
    $services->alias(MonotonicClockInterface::class, PlatformMonotonicClock::class);

    $services->set(PasswordVerification::class);
    $services->set(PasswordAuthenticator::class);
    $services->set(PendingLoginVerification::class);
    $services->set(LoginCompletion::class);
    $services->set(SecondFactorRequirement::class);
    $services->set(PasskeyEnrolment::class);
    $services->set(TicketIssuing::class);
    $services->set(TicketRedeeming::class);
    $services->set(CredentialTicketRefusal::class);
    $services->set(EnrolmentTicketIssue::class);
    $services->set(EnrolmentTicketRedemption::class);
    $services->set(PasswordTicketIssue::class);
    $services->set(PasswordTicketRedemption::class);
    $services->set(TotpTicketIssue::class);
    $services->set(TotpTicketRedemption::class);
    $services->set(PresentedTicket::class);
    $services->set(TicketLink::class)->arg('$router', service(ProviderRoutes::URL_GENERATOR));
    $services->set(PasskeyAuthentication::class);
    $services->set(BackupCodeSet::class);
    $services->set(BackupCodesRenewal::class);
    $services->set(TotpEnrolment::class);
    $services->set(TotpAuthentication::class);
    $services->set(CredentialRevocation::class);
    $services->set(EnrolmentRefusal::class);
    $services->set(TenantHardening::class);
    $services->set(TenantContactAdoption::class);
    $services->set(PasswordChange::class)->arg('$attempts', service('beffroi.security.password_change_attempts'));
    $services->set(BreachedPasswordRefusal::class);
    $services->set(BreachedPasswordLookup::class);
    $services->set(CredentialRenaming::class);
    $services->set(ActiveCredentials::class);
    $services->set(DeclaredModels::class);
    $services->set(ActivePassword::class);
    $services->set(SessionOpener::class);
    $services->set(OtherSessionsTermination::class);
    $services->set(ProvedMethods::class);
    $services->set(SessionTerminator::class);
    $services->set(AuthenticationRefusal::class);
    $services->set(UserProvisioner::class);
    $services->set(PersonCreation::class);
    $services->set(PersonDisabling::class);
    $services->set(PersonEnabling::class);
    $services->set(IdentityLinker::class);
    $services->set(UpstreamMemberships::class);
    $services->set(JustInTimeProvisioning::class);
    $services->set(GroupProvisioner::class);
    $services->set(LocalMemberships::class);
    $services->set(ConfigurationAdministratorGroups::class);
    $services->alias(AdministratorGroupsInterface::class, ConfigurationAdministratorGroups::class);
    $services->set(Administrators::class);
    $services->set(FederatedDomains::class);
    $services->set(SamlUpstreamProviders::class);
    $services->alias(UpstreamProvidersInterface::class, SamlUpstreamProviders::class);

    $services->set(SecretDrawer::class);
    $services->set(UserCodeDrawer::class);

    // The provider tags no type: a deployment that serves rich authorization requests tags those of its domain.
    $services->set(ServedAuthorizationDetailTypes::class)->args([tagged_iterator('beffroi.oidc.authorization_detail_type')]);
    $services->alias(AuthorizationDetailsReaderInterface::class, ServedAuthorizationDetailTypes::class);
    $services->alias(ServedAuthorizationDetailTypesInterface::class, ServedAuthorizationDetailTypes::class);
    $services->alias('beffroi.authorization_detail_types', AuthorizationDetailsReaderInterface::class)->public();

    $services->set(ClientMetadataReader::class);

    $services->set(ConfigurationClientRepository::class)->tag('beffroi.oidc.client_source')->tag('beffroi.oidc.client_inventory');
    // Only stored clients are tagged for the removal of unused ones: a declared client is never deleted.
    $services->set(DoctrineClientRepository::class)->tag('beffroi.oidc.client_inventory')->tag('beffroi.oidc.unused_clients');
    $services
        ->set(RegistrationsReadOncePerRequest::class)
        ->args([service(DoctrineClientRepository::class)])
        ->tag('beffroi.oidc.client_source')->tag('kernel.reset', [
        'method' => 'reset',
    ]);
    $services->set(RegisteredClients::class)->args([tagged_iterator('beffroi.oidc.client_source')]);
    $services->alias(ClientRepositoryInterface::class, RegisteredClients::class);
    $services->alias(PushedAuthorizationRequirementInterface::class, RegisteredClients::class);
    $services->alias(RegisteredResourcesInterface::class, RegisteredClients::class);
    $services->alias(RegisteredScopesInterface::class, RegisteredClients::class);
    $services->alias(RegisteredAccessTokenShapesInterface::class, RegisteredClients::class);
    $services->alias(UnsignedRequestObjectsInterface::class, RegisteredClients::class);
    $services->set(ClientInventory::class)->args([tagged_iterator('beffroi.oidc.client_inventory')]);
    $services->alias(ClientInventoryInterface::class, ClientInventory::class);
    $services->alias(ClientStoreInterface::class, DoctrineClientRepository::class);
    $services->set(ClientIdentifierDrawer::class);
    $services->set(ConfigurationClientRegistrationPolicy::class);
    $services->alias(ClientRegistrationPolicyInterface::class, ConfigurationClientRegistrationPolicy::class);
    $services->alias(ClientRetentionPolicyInterface::class, ConfigurationClientRegistrationPolicy::class);
    // Wiring a mode opens it for nobody: only a tenant whose policy names it reaches it.
    $services->set(DoctrineInitialAccessTokenRepository::class);
    $services->alias(InitialAccessTokenRepositoryInterface::class, DoctrineInitialAccessTokenRepository::class);
    $services->alias(IssuedInitialAccessTokensInterface::class, DoctrineInitialAccessTokenRepository::class);
    $services->set(InitialAccessTokenIssuance::class);
    $services->set(InitialAccessTokenRevocation::class);
    $services->set(InitialAccessTokenAuthorization::class)->tag('beffroi.oidc.registration_mode');
    $services->set(OpenRegistrationAuthorization::class)->tag('beffroi.oidc.registration_mode');
    // A pool of its own, so that nothing remembered here can satisfy the guard of an assertion.
    $services->set(SoftwareStatementReplayGuard::class)->args([
        inline_service(SeenOnce::class)->args([service('beffroi.software_statements'), service('lock.factory')]),
    ]);
    $services->alias(SoftwareStatementReplayGuardInterface::class, SoftwareStatementReplayGuard::class);
    $services->set(SoftwareStatementVerifier::class);
    $services->set(SoftwareStatementAuthorization::class)->tag('beffroi.oidc.registration_mode');
    $services->set(RegistrationAuthorizations::class)->args([tagged_iterator('beffroi.oidc.registration_mode')]);
    $services->set(RegistrationHeldToTheTenant::class);
    $services->set(RegistrationSignedWithHeldKeys::class);
    $services->set(SectorIdentifierDocumentFetcher::class)->tag(ThirdPartyRequestsPass::TAG);
    $services->alias(SectorIdentifierDocumentFetcherInterface::class, SectorIdentifierDocumentFetcher::class);
    $services->set(RegistrationHeldToItsSector::class);
    $services->set(RegistrationUnderThePolicy::class);
    $services->set(ClientRegistrationHandler::class);
    $services->set(ClientConfigurationAccess::class);
    $services->set(ClientConfigurationReader::class);
    $services->set(ClientConfigurationReplacement::class);
    $services->set(ClientConfigurationRemoval::class);
    $services->set(RegisteredClientRemoval::class);
    $services->set(ClientUseRecording::class);
    $services->set(UnusedClientRemoval::class)->args([tagged_iterator('beffroi.oidc.unused_clients')]);
    // The first one tagged is what a client that names none registers.
    $services->set(ClientSecretBasic::class)->tag('beffroi.client_authentication_method');
    $services->set(ClientSecretPost::class)->tag('beffroi.client_authentication_method');
    $services->set(PrivateKeyJwt::class)->tag('beffroi.client_authentication_method');
    $services->set(ClientSecretJwt::class)->tag('beffroi.client_authentication_method');
    $services->set(NoAuthentication::class)->tag('beffroi.client_authentication_method');
    // Only a host that asks for a certificate hands one to PHP, and tls_client_auth trusts no certificate no named authority issued.
    $services->set(TlsClientAuth::class);
    $services->set(SelfSignedTlsClientAuth::class);
    $services->set(PkiFrameworkCertificateAuthorities::class);
    $services->alias(ClientCertificateAuthoritiesInterface::class, PkiFrameworkCertificateAuthorities::class);
    $services->set(ClientAuthenticationMethods::class)->args([
        inline_service(SwitchedServices::class)->args([
            inline_service(SwitchedServices::class)->args([
                tagged_iterator('beffroi.client_authentication_method'),
                service(MutualTlsSection::AUTHORITIES_ROLE),
                iterator([service(TlsClientAuth::class)]),
            ]),
            service(MutualTlsSection::ROLE),
            iterator([service(SelfSignedTlsClientAuth::class)]),
        ]),
    ]);
    $services->alias(ClientAuthenticationMethodsInterface::class, ClientAuthenticationMethods::class);
    $services->set(ClientAuthenticationRequestParser::class);
    $services->set(ClientAuthenticator::class);
    $services->set(PkiFrameworkCertificateReader::class);
    $services->alias(CertificateReaderInterface::class, PkiFrameworkCertificateReader::class);
    $services->set(JwtLibraryCompactJwtReader::class);
    $services->alias(CompactJwtReaderInterface::class, JwtLibraryCompactJwtReader::class);
    $services->set('beffroi.oidc.client_assertion.signature_algorithms', AlgorithmManager::class)->factory([
        service(JoseSignatureAlgorithms::class),
        'manager',
    ]);
    $services->set(JwtLibraryJwtKeyVerifier::class)->args([service('beffroi.oidc.client_assertion.signature_algorithms')]);
    $services->alias(JwtKeyVerifierInterface::class, JwtLibraryJwtKeyVerifier::class);
    $services->set('beffroi.oidc.client_encryption.algorithms', AlgorithmManager::class)->factory([service(JoseEncryptionAlgorithms::class), 'manager']);
    $services->set(JwtLibraryJweEncrypter::class)->args([service('beffroi.oidc.client_encryption.algorithms')]);
    $services->alias(JweEncrypterInterface::class, JwtLibraryJweEncrypter::class);
    $services->set(ClientDocumentIssuer::class);
    $services->set('beffroi.oidc.client_assertion.mac_algorithms', AlgorithmManager::class)->args([[inline_service(HS256::class)]]);
    $services->set(JwtLibraryClientAssertionSecretVerifier::class)->args([service('beffroi.oidc.client_assertion.mac_algorithms')]);
    $services->alias(ClientAssertionSecretVerifierInterface::class, JwtLibraryClientAssertionSecretVerifier::class);
    $services->set(ClientAssertionValidator::class);
    $services->set(AcceptedAssertionAudiences::class);
    $services->set(ClientKeySetProvider::class)->args([service('beffroi.oidc.client_keys.provider')]);
    $services->set(ClientJwksFetcher::class)->tag(ThirdPartyRequestsPass::TAG);
    $services->alias(ClientJwksFetcherInterface::class, ClientJwksFetcher::class);
    $services->set('beffroi.oidc.client_keys.cache', ClientJwksCache::class)->args([
        '$cache' => service('beffroi.client_keys'),
    ]);
    $services->set('beffroi.oidc.client_keys.provider', PublishedKeySetProvider::class)->args([
        '$cache' => service('beffroi.oidc.client_keys.cache'),
    ]);
    $services->set(ClientAssertionReplayGuard::class)->args([
        inline_service(SeenOnce::class)->args([service('beffroi.client_assertions'), service('lock.factory')]),
    ]);
    $services->alias(ClientAssertionReplayGuardInterface::class, ClientAssertionReplayGuard::class);

    // Nothing is shared with the client assertions above, so that one reading cannot satisfy the other.
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
        inline_service(SeenOnce::class)->args([service('beffroi.issuer_assertions'), service('lock.factory')]),
    ]);
    $services->alias(IssuerAssertionReplayGuardInterface::class, IssuerAssertionReplayGuard::class);

    $services->set(JwtLibraryProofKeyVerifier::class)->args([service('beffroi.oidc.client_assertion.signature_algorithms')]);
    $services->alias(ProofKeyVerifierInterface::class, JwtLibraryProofKeyVerifier::class);
    $services->set(CachedDpopProofReplayGuard::class)->args([
        inline_service(SeenOnce::class)->args([service('beffroi.dpop'), service('lock.factory')]),
    ]);
    $services->alias(DpopProofReplayGuardInterface::class, CachedDpopProofReplayGuard::class);
    $services->set(NoDpopNonce::class);
    $services->set(CachedDpopNonce::class)->args([
        '$cache' => service('beffroi.dpop'),
    ]);
    $services->set(DpopProofValidator::class);
    $services->set(DpopProofVerifier::class);
    $services->set(DpopChallengeParameters::class);
    $services->alias(ChallengeParametersInterface::class, DpopChallengeParameters::class);

    // The first subject type tagged is what a client that registers none takes, and the sector identifier
    // sources are read in the order they are wired.
    $services->set(IdentifiersWithoutARedirection::class);
    $services->set(RegisteredSectorIdentifier::class)->tag('beffroi.oidc.sector_identifier_source');
    $services->set(RedirectUriSectorIdentifier::class)->tag('beffroi.oidc.sector_identifier_source');
    $services->set(JwksUriSectorIdentifier::class)->tag('beffroi.oidc.sector_identifier_source');
    $services->set(SectorIdentifiers::class)->args([tagged_iterator('beffroi.oidc.sector_identifier_source')]);
    $services->alias(SectorIdentifiersInterface::class, SectorIdentifiers::class);
    $services->set(PublicSubjectIdentifierResolver::class)->tag('beffroi.oidc.subject_type');
    $services->set(PairwiseSubjectIdentifierResolver::class)->tag('beffroi.oidc.subject_type');
    $services->set(AssignedSubjectIdentifiers::class)->args([tagged_iterator('beffroi.oidc.subject_type')]);
    $services->alias(SubjectIdentifierResolverInterface::class, AssignedSubjectIdentifiers::class);
    $services->alias(SubjectIdentifierOpenerInterface::class, AssignedSubjectIdentifiers::class);
    $services->alias(PresentedSubjectReaderInterface::class, AssignedSubjectIdentifiers::class);
    $services->alias(AssignedSubjectTypesInterface::class, AssignedSubjectIdentifiers::class);
    $services->set(FilePairwiseSalt::class);
    $services->alias(PairwiseSaltInterface::class, FilePairwiseSalt::class);
    $services->set(DoctrinePairwiseSubjectRepository::class);
    $services->alias(PairwiseSubjectRepositoryInterface::class, DoctrinePairwiseSubjectRepository::class);
    $services->set(StandardClaimsProvider::class)->tag('beffroi.oidc.claims_provider');
    $services->set(ServedClaims::class)->args([tagged_iterator('beffroi.oidc.claims_provider')]);
    $services->alias(ClaimsProviderInterface::class, ServedClaims::class);
    $services->set(ClaimsAskedByName::class);
    $services->set(ConfigurationDeclaredScopes::class);
    $services->alias(DeclaredScopesInterface::class, ConfigurationDeclaredScopes::class);
    $services->set(ConfigurationAdministrationResource::class);
    $services->alias(AdministrationResourceInterface::class, ConfigurationAdministrationResource::class);
    $services->set(AdministrationAudience::class);
    $services->set(AdministratorOfARequest::class);
    $services->set(PersonsOfTheTenant::class);
    $services->set(PersonDelivery::class);
    $services->set(AdministeredPerson::class);
    $services->set(AdministeredSessions::class);
    $services->set(AdministeredJournal::class);
    $services->set(AdministeredSessionEnd::class);
    $services->set(AdministeredCredentialRevocation::class);
    $services->set(AdministeredPersonCreation::class);
    $services->set(AdministeredDescription::class);
    $services->set(AdministeredDisabling::class);
    $services->set(AdministeredConsents::class);
    $services->set(AdministeredClientRemoval::class);
    $services->set(AdministeredGroups::class);
    $services->set(AdministeredGroupCreation::class);
    $services->set(AdministeredTenantContact::class);
    $services->set(AdministeredMemberships::class);
    $services->set(AdministeredEnabling::class);
    $services->set(AdministeredEnrolmentTicket::class);
    $services->set(AdministeredPasswordTicket::class);
    $services->set(AdministeredTotpTicket::class);
    $services->set(PersonsDelivered::class);
    // The limit and the interval are filled in by AdministratorSection.
    $services->set(RateLimitedPersonsBudget::class)->args([
        '$storage' => inline_service(CacheStorage::class)->args([service('cache.rate_limiter')]),
        '$locks' => service('lock.factory'),
    ]);
    $services->alias(PersonsBudgetInterface::class, RateLimitedPersonsBudget::class);
    $services->set(PersonsRefusalListener::class);
    $services->set(OfferedScopes::class);
    $services->alias(OfferedScopesInterface::class, OfferedScopes::class);

    $services->set(Sha256CodeChallengeMethod::class)->tag('beffroi.oidc.code_challenge_method');
    $services->set(CodeChallengeMethods::class)->args([tagged_iterator('beffroi.oidc.code_challenge_method')]);
    $services->alias(CodeChallengeMethodsInterface::class, CodeChallengeMethods::class);
    // Public: a DBAL type cannot be injected into, so BeffroiKernelTrait::boot() hands it this service.
    $services->alias('beffroi.code_challenge_methods', CodeChallengeMethodsInterface::class)->public();

    $services->set(AuthorizationRequestParser::class);
    $services->set(PushedAuthorizationRequestResolver::class);
    $services->set(RequestObjectValidator::class);
    $services->set(RequestObjectReader::class);
    $services->set(RequestObjectResolver::class);
    $services->set(RequestObjectReplayGuard::class)->args([
        inline_service(SeenOnce::class)->args([service('beffroi.request_objects'), service('lock.factory')]),
    ]);
    $services->alias(RequestObjectReplayGuardInterface::class, RequestObjectReplayGuard::class);
    $services->set(RequestObjectFetcher::class)->tag(ThirdPartyRequestsPass::TAG);
    $services->alias(RequestObjectFetcherInterface::class, RequestObjectFetcher::class);
    $services->set(PushedAuthorizationHandler::class);
    $services->set(DeviceAuthorizationHandler::class);
    $services->set(DeviceApproval::class);
    $services->set(PollDelivery::class)->tag('beffroi.oidc.ciba_delivery_mode');
    $services->set(PingDelivery::class)->tag('beffroi.oidc.ciba_delivery_mode');
    $services->set(ServedDeliveryModes::class)->args([tagged_iterator('beffroi.oidc.ciba_delivery_mode')]);
    $services->alias(ServedDeliveryModesInterface::class, ServedDeliveryModes::class);
    $services->set(IdTokenUserHint::class)->tag('beffroi.oidc.ciba_user_hint');
    // The deployment names one of these per side (LoginHintReadings): two readings of one "login_hint" could disagree.
    $services->set(SubjectLoginHint::class);
    $services->set(UsernameLoginHint::class);
    $services->set(UserHints::class);
    $services->set(SignedBackchannelRequest::class);
    $services->set(BackchannelAuthenticationHandler::class)->arg('$sealer', service(KeysSection::BACKCHANNEL_SEALER));
    $services->set(ApprovalAuthenticationRequirement::class);
    $services->set(BackchannelApproval::class)->arg('$sealer', service(KeysSection::BACKCHANNEL_SEALER));
    $services->set(RequestObjectJweKind::class)->tag('beffroi.key_bound_artifact');
    $services->set(PushedRequestJweKind::class)->tag('beffroi.key_bound_artifact');
    $services->set(IdTokenHintVerifier::class);
    $services->set(AuthenticationRequirement::class);
    $services->set(AuthorizationCodeIssuer::class);
    $services->set(RequiredConsent::class);
    $services->set(AuthorizationHandler::class);
    $services->set(ConsentGranting::class);
    $services->set(SharedIdentity::class);
    $services->set(ThirdPartyInitiatedLoginHandler::class);
    $services->set(LoginHints::class);
    $services->set(ConsentRevocation::class);
    $services->set(ResponseDocumentIssuer::class);

    // The first one tagged is the shape a client that names none takes.
    $services->set(SealedPerson::class)->arg('$sealer', service(KeysSection::PERSON_SEALER));
    $services->set(JwtAccessTokenIssuer::class)->tag('beffroi.oidc.access_token_issuer');
    $services->set(OpaqueAccessTokenIssuer::class)->tag('beffroi.oidc.access_token_issuer');
    $services->set(ServedAccessTokenShapes::class)->args([tagged_iterator('beffroi.oidc.access_token_issuer')]);
    // every access token, whatever grant asks for it, minted under the reservation of the administration API
    // (decision 0038): what the grants are handed is the guard, the shapes behind it
    $services->set(AdministrationAudienceGuard::class)->arg('$issuer', service(ServedAccessTokenShapes::class));
    $services->alias(AccessTokenIssuerInterface::class, AdministrationAudienceGuard::class);
    $services->alias(ServedAccessTokenShapesInterface::class, ServedAccessTokenShapes::class);
    $services->set(JwtIdTokenIssuer::class);
    $services->alias(IdTokenIssuerInterface::class, JwtIdTokenIssuer::class);
    $services->set(IdTokenJwsKind::class)->tag('beffroi.key_bound_artifact');
    $services->set(AccessTokenJwsKind::class)->tag('beffroi.key_bound_artifact');
    $services->set(ResponseDocumentJwsKind::class)->tag('beffroi.key_bound_artifact');
    $services->set(TokenIssuer::class);
    $services->set(RefreshTokenRevocation::class);
    $services->set(RefreshTokenDue::class);
    $services->set(RequestedAuthorizationDetails::class);
    $services->set(AuthorizationCodeGrant::class)->tag('beffroi.oidc.grant');
    $services->set(RefreshTokenGrant::class)->tag('beffroi.oidc.grant');
    $services->set(ClientCredentialsGrant::class)->tag('beffroi.oidc.grant');
    $services->set(DeviceCodeGrant::class)->tag('beffroi.oidc.grant');
    $services->set(BackchannelAuthenticationGrant::class)->tag('beffroi.oidc.grant');
    $services->set(TokenExchangeGrant::class)->tag('beffroi.oidc.grant');
    $services->set(JwtBearerGrant::class)->tag('beffroi.oidc.grant');
    $services->set(ServedGrants::class)->args([tagged_iterator('beffroi.oidc.grant')]);
    $services->alias(ServedGrantsInterface::class, ServedGrants::class);
    // The closings are read in the order they are wired.
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
    $services->set(PresentedAccessTokenType::class)->tag('beffroi.oidc.presented_token_type');
    $services->set(PresentedTokenTypes::class)->args([tagged_iterator('beffroi.oidc.presented_token_type')]);
    $services->alias(PresentedTokenTypesInterface::class, PresentedTokenTypes::class);
    $services->set(TokenHandler::class);
    $services->set(RecordedGrants::class)->args([tagged_iterator('beffroi.oidc.grant_record')]);
    $services->alias(RecordedGrantsInterface::class, RecordedGrants::class);
    $services->alias(CanRevokeGrantsByConsentInterface::class, RecordedGrants::class);
    $services->set(CertificateConfirmationKind::class)->tag('beffroi.oidc.confirmation_kind');
    $services->set(KeyConfirmationKind::class)->tag('beffroi.oidc.confirmation_kind');
    $services->set(Confirmations::class)->args([tagged_iterator('beffroi.oidc.confirmation_kind')]);
    $services->alias(ConfirmationReaderInterface::class, Confirmations::class);
    $services->alias(ServedTokenSchemesInterface::class, Confirmations::class);
    $services->alias('beffroi.confirmations', ConfirmationReaderInterface::class)->public();

    $services->set(JwtAccessTokenVerifier::class)->tag('beffroi.oidc.access_token_verifier');
    $services->set(OpaqueAccessTokenVerifier::class)->tag('beffroi.oidc.access_token_verifier');
    $services->set(AccessTokenVerifier::class)->args([tagged_iterator('beffroi.oidc.access_token_verifier')]);
    $services->set(PersonOfAnAccessToken::class);
    $services->set(AccessTokenInspector::class);
    $services->set(PresentedAccessTokenParser::class);

    $services->set(UserInfoHandler::class);
    $services->set(IntrospectionHandler::class);
    $services->set(RevocationHandler::class);
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
    $services->set(AnnouncedUiLocales::class)->tag('beffroi.oidc.metadata');
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
    $services->set(SelfSignedCertificateIssuer::class);
    $services->alias(CertificateIssuerInterface::class, SelfSignedCertificateIssuer::class);
    $services->set(ModelMetadataWriter::class);
    $services->alias(MetadataWriterInterface::class, ModelMetadataWriter::class);
    $services->set(ModelServiceProviderMetadataWriter::class);
    $services->alias(ServiceProviderMetadataWriterInterface::class, ModelServiceProviderMetadataWriter::class);
    $services->set(RouterIdentityProviderEndpoints::class);
    $services->alias(IdentityProviderEndpointsInterface::class, RouterIdentityProviderEndpoints::class);
    $services->set(SigningCertificates::class);
    $services->set(EncryptionCertificates::class);
    $services->set(UpstreamDecryptionKeys::class);
    // SamlSection hands ConfigurationServiceProviders the declarations and the slug of the tenant.
    $services->set(ProviderServedClaims::class);
    $services->alias(ServedClaimsInterface::class, ProviderServedClaims::class);
    $services->set(ConfigurationServiceProviders::class)->args([
        '$tenantSlug' => '',
        '$definitions' => [],
    ]);
    $services->alias(ServiceProvidersInterface::class, ConfigurationServiceProviders::class);
    // ServiceProvidersPass and UpstreamIdentityProvidersPass hand it the declarations.
    $services->set(MappedClaimsWarmer::class)->args([
        '$declarations' => [],
        '$upstreamDeclarations' => [],
    ]);
    $services->set(ModelServiceProviderMetadataReader::class);
    $services->alias(ServiceProviderMetadataReaderInterface::class, ModelServiceProviderMetadataReader::class);
    $services->set(MetadataFetcher::class);
    $services->alias(MetadataFetcherInterface::class, MetadataFetcher::class);
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
    // SamlSection hands ConfigurationUpstreamIdentityProviders the declarations and the slug of the tenant.
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
    // The table of the upstream identity providers, not the one of the service providers the port is aliased to.
    $services->set(ModelAuthnRequestSender::class)->arg('$accepted', service('beffroi.saml.identity_providers.accepted_metadata'));
    $services->alias(AuthnRequestSenderInterface::class, ModelAuthnRequestSender::class);
    $services->set(UpstreamSignOns::class);
    $services->set(UpstreamSignOnAnswer::class);
    $services->set(UpstreamLoginRequirement::class);
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
    $services->set(FrontChannelLogoutRenderer::class)->tag('beffroi.logout_channel');
    $services->set(LogoutChannels::class)->args([tagged_iterator('beffroi.logout_channel')]);
    $services->alias(ServedLogoutChannelsInterface::class, LogoutChannels::class);
    $services->set(LogoutTokenDeliveryBudget::class);
    $services->alias(LogoutTokenDeliveryInterface::class, LogoutTokenDeliveryBudget::class);
    $services->set(QueuedLogoutTokenRetries::class);
    $services->alias(LogoutTokenRetriesInterface::class, QueuedLogoutTokenRetries::class);
    $services->set(LogoutTokenJwsKind::class)->tag('beffroi.key_bound_artifact');
};
