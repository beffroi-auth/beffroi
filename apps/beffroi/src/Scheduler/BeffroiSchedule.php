<?php

declare(strict_types=1);

namespace App\Scheduler;

use App\Message\AdvanceKeyLifecycle;
use App\Message\ForgetTheActsPastTheirRetention;
use App\Message\ForgetTheChangesPastTheirRetention;
use App\Message\ForgetTheExpiredArchives;
use App\Message\ForgetTheRecordsThatAreDead;
use App\Message\RefreshTheAddressDatabases;
use App\Message\RefreshTheSamlMetadata;
use App\Message\RemoveUnusedClients;
use App\Message\SignTheChains;
use Symfony\Component\Scheduler\Attribute\AsSchedule;
use Symfony\Component\Scheduler\RecurringMessage;
use Symfony\Component\Scheduler\Schedule;
use Symfony\Component\Scheduler\ScheduleProviderInterface;

/**
 * One worker at a time consumes the transport "scheduler_beffroi": the steps are idempotent but not concurrent.
 */
#[AsSchedule(BeffroiSchedule::NAME)]
final readonly class BeffroiSchedule implements ScheduleProviderInterface
{
    public const string NAME = 'beffroi';

    public const string KEY_LIFECYCLE_EVERY = '1 minute';

    public const string UNUSED_CLIENTS_EVERY = '1 hour';

    public const string JOURNAL_RETENTION_EVERY = '1 day';

    /**
     * In seconds: what a chain holds past its last signature is held by its links alone.
     */
    public const int CHAIN_SIGNATURE_EVERY = 300;

    /**
     * An hour and not a day: an archive holds everything known of a person in clear at once.
     */
    public const string EXPIRED_ARCHIVES_EVERY = '1 hour';

    public const string HISTORY_RETENTION_EVERY = '1 day';

    /**
     * MaxMind publishes the city edition on Tuesdays and Fridays and the ASN edition every weekday.
     */
    public const string ADDRESS_DATABASES_EVERY = '1 week';

    public const string DEAD_RECORDS_EVERY = '1 hour';

    /**
     * The cacheDuration of the metadata is not read: how long to keep a document is this provider's to say.
     */
    public const string SAML_METADATA_EVERY = '1 hour';

    public function getSchedule(): Schedule
    {
        return new Schedule()
            ->add(RecurringMessage::every(self::KEY_LIFECYCLE_EVERY, new AdvanceKeyLifecycle()))
            ->add(RecurringMessage::every(
                self::UNUSED_CLIENTS_EVERY,
                new RemoveUnusedClients(),
            ))
            ->add(RecurringMessage::every(self::JOURNAL_RETENTION_EVERY, new ForgetTheActsPastTheirRetention()))
            ->add(RecurringMessage::every(self::CHAIN_SIGNATURE_EVERY, new SignTheChains()))
            ->add(RecurringMessage::every(
                self::EXPIRED_ARCHIVES_EVERY,
                new ForgetTheExpiredArchives(),
            ))
            ->add(RecurringMessage::every(
                self::HISTORY_RETENTION_EVERY,
                new ForgetTheChangesPastTheirRetention(),
            ))
            ->add(RecurringMessage::every(
                self::ADDRESS_DATABASES_EVERY,
                new RefreshTheAddressDatabases(),
            ))
            ->add(RecurringMessage::every(
                self::DEAD_RECORDS_EVERY,
                new ForgetTheRecordsThatAreDead(),
            ))
            ->add(RecurringMessage::every(
                self::SAML_METADATA_EVERY,
                new RefreshTheSamlMetadata(),
            ));
    }
}
