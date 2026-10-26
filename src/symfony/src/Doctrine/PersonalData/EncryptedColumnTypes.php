<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\PersonalData;

use function array_keys;
use function count;
use function implode;
use Beffroi\Core\Exception\InvalidArgumentException;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\EncryptedTypes;
use Symfony\Component\KeyManagement\EnvelopeDecrypterInterface;
use Symfony\Component\KeyManagement\EnvelopeEncrypterInterface;
use function in_array;
use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;

/**
 * The encrypted Doctrine types of the bundle, one per family of columns and per type the family seals
 * (decisions 0011 and 0018): the family is the scope the data key of a tenant is minted under, and the
 * type it seals is the one the column had, because an encrypted type decorates a type and the domain a
 * column carries does not change.
 *
 * They are declared here and nowhere else, and every mapping of the spike names one of them, so that a
 * column which seals and a column which does not are told apart by the type the mapping gives it and by
 * nothing kept beside it: the model says which of its fields is a personal datum and the walk of the
 * schema reads this class to hold the two together. They cannot be declared through `doctrine.dbal.types`
 * the way the other 33 types of the bundle are: that option names a class DoctrineBundle instantiates with
 * no argument, and an encrypted type takes an encrypter, which is a service. What the bridge asks for
 * instead is an `EncryptedTypes` service whose `register()` runs while the bundles boot
 * (`BeffroiBundle::boot()`), early enough for the front controller, the console with its schema tool and
 * its migrations, and the test kernel, all at once.
 *
 * **Three things a mapping stops being able to say once its column seals**, written here because here is
 * where a reader of that mapping is sent.
 *
 * - **The column becomes unbounded binary.** `EncryptedType::getSQLDeclaration()` drops the `length` and
 *   asks the platform for a blob, so the `length` a mapping carries describes the plaintext and nothing
 *   else. It is kept because it is the length the domain checks, not because the column is that wide.
 * - **An option that describes the stored value stops being true.** `beffroi_user.address` loses its
 *   `jsonb: true`, and with it anything a query could have done with the JSON: what is in the column is
 *   the ciphertext of a JSON document, which no operator of the database can read into.
 * - **A ciphertext is not bound to its row.** The type passes no authenticated data, having nowhere to
 *   take any from: it never sees the table, the column or the row. So within one tenant and one scope, a
 *   value moved into another row of the same column decrypts there, where the sealed keys and the sealed
 *   secrets of the key custody are bound by tenant and by use (`TenantEnvelope`). That is a line of the
 *   page for a CISO and not a defect to hide, and what would let the read path name the column is a change
 *   in the bridge, not a class here.
 */
final readonly class EncryptedColumnTypes
{
    /**
     * The prefix of every name this class derives, which is also what tells an encrypted type of the
     * bundle from the 33 types that are not (`BeffroiBundle::DBAL_TYPES`).
     */
    public const string PREFIX = 'beffroi_encrypted_';

    /**
     * The families of columns this spike seals, by the scope their data key is minted under, each naming
     * the types its own columns carry. The scope is the name of the table without the prefix of the
     * bundle, so that a family is read from the schema and never from a second list; the tenant is not in
     * it, being what the encrypter puts there from the tenant that is ambient, which no type can know
     * (decision 0018).
     *
     * A family holds several types because a type seals one type: every column of `beffroi_user` shares one
     * data key, and the six types below are six ways into it. What the count of keys per tenant is, is
     * therefore the count of families and not the count of types.
     *
     * @var array<string, list<string>>
     */
    public const array FAMILIES = [
        'user' => ['string', 'text', 'beffroi_email_address', 'beffroi_address', 'beffroi_profile', 'beffroi_user_source'],
        'linked_identity' => ['string', 'json'],
        'passkey_credential' => ['string'],
        'push_subscription' => ['string', 'text'],
        'authentication_session' => ['beffroi_request_context'],
        'interaction' => ['text'],
        'pushed_authorization_request' => ['json'],
        'device_authorization_request' => ['beffroi_request_context'],
        'backchannel_authentication_request' => ['beffroi_binding_message', 'beffroi_request_context'],
        'client' => ['json', 'beffroi_client_secret'],
        'journal' => ['beffroi_request_context'],
        'personal_archive' => ['text'],
        'claim_change' => ['string', 'beffroi_request_context'],
        'disclosure' => ['beffroi_scopes', 'beffroi_claims_request', 'beffroi_authorization_details'],
        'saml_service_provider' => ['text'],
        'saml_upstream_identity_provider' => ['text'],
    ];

    /**
     * The name a mapping gives the column of a family that seals a type, derived and not listed: a list of
     * names beside the families is a second place to be wrong, and a mapping that names a type this rule
     * does not produce is a mapping no encrypter answers.
     *
     * @throws InvalidArgumentException if that family does not seal that type
     */
    public static function name(string $family, string $type): string
    {
        if (! in_array($type, self::FAMILIES[$family] ?? [], true)) {
            throw new InvalidArgumentException(sprintf(
                'The family "%s" seals no column of type "%s". The families are %s.',
                $family,
                $type,
                implode(', ', array_keys(self::FAMILIES)),
            ));
        }

        return self::PREFIX . $family . '_' . (str_starts_with($type, 'beffroi_') ? substr($type, strlen('beffroi_')) : $type);
    }

    /**
     * What the `EncryptedTypes` service of the bundle is declared with: the name of every type, the type it
     * decorates, and the scope it seals under.
     *
     * @return array<string, array{type: string, key: string}>
     */
    public static function declarations(): array
    {
        $declarations = [];
        foreach (self::FAMILIES as $family => $types) {
            foreach ($types as $type) {
                $declarations[self::name($family, $type)] = [
                    'type' => $type,
                    'key' => $family,
                ];
            }
        }

        return $declarations;
    }

    /**
     * The service the bundles register on boot (`BeffroiBundle::boot()`), built here so that the declaration
     * and its construction are one thing: what a deployment chooses is the encrypter and nothing else, and
     * that choice is what decides where the data key of a scope comes from.
     */
    public static function service(EnvelopeEncrypterInterface&EnvelopeDecrypterInterface $envelopes): EncryptedTypes
    {
        return new EncryptedTypes($envelopes, self::declarations());
    }

    /**
     * The names of every encrypted type of the bundle, which is what tells a column that seals from one
     * that does not when the schema is read.
     *
     * @return list<string>
     */
    public static function names(): array
    {
        return array_keys(self::declarations());
    }

    /**
     * The family each of those names seals under, by the name a mapping gives the type: what a reader of
     * the schema needs to tell a column sealed under the scope of its own table from one sealed under
     * another's, which is what the walk of the classification refuses (`Sealed` of the core).
     *
     * @return array<string, string>
     */
    public static function familyByType(): array
    {
        $families = [];
        foreach (self::declarations() as $name => $declaration) {
            $families[$name] = $declaration['key'];
        }

        return $families;
    }

    /**
     * The families themselves, which is the one list of the scopes a tenant holds a data key for: what the
     * console says of a tenant that holds none, and what the walk of the schema holds the classification
     * to.
     *
     * @return list<string>
     */
    public static function families(): array
    {
        return array_keys(self::FAMILIES);
    }

    /**
     * How many data keys a tenant holds for its columns, which is the count of families and not of types:
     * the arithmetic decision 0018 does when it says what a worker keeps open.
     */
    public static function familyCount(): int
    {
        return count(self::FAMILIES);
    }
}
