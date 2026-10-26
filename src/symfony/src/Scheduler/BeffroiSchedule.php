<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Scheduler;

use Beffroi\Bundle\Message\AdvanceKeyLifecycle;
use Beffroi\Bundle\Message\ForgetTheActsPastTheirRetention;
use Beffroi\Bundle\Message\ForgetTheChangesPastTheirRetention;
use Beffroi\Bundle\Message\ForgetTheExpiredArchives;
use Beffroi\Bundle\Message\ForgetTheRecordsThatAreDead;
use Beffroi\Bundle\Message\RefreshTheAddressDatabases;
use Beffroi\Bundle\Message\RefreshTheSamlMetadata;
use Beffroi\Bundle\Message\RemoveUnusedClients;
use Symfony\Component\Scheduler\Attribute\AsSchedule;
use Symfony\Component\Scheduler\RecurringMessage;
use Symfony\Component\Scheduler\Schedule;
use Symfony\Component\Scheduler\ScheduleProviderInterface;

/**
 * What time does on its own (architecture §5.6): one recurring message per timed step, handled on the
 * command bus like every write. The transport is "scheduler_beffroi"; the worker that consumes the buses
 * consumes it too, and one worker at a time does, the steps being idempotent but not concurrent.
 */
#[AsSchedule(BeffroiSchedule::NAME)]
final readonly class BeffroiSchedule implements ScheduleProviderInterface
{
    public const string NAME = 'beffroi';

    /**
     * The precision of the two windows of a rotation, minutes long at the least.
     */
    public const string KEY_LIFECYCLE_EVERY = '1 minute';

    /**
     * What the removal of the clients nobody uses any more is worth waiting for (decision 0009): the
     * durations it reads are days long, a run is bounded and the next one takes what it left, so an hour is
     * short enough that a backlog is worked through and long enough that a deployment with nothing to drop
     * reads its table once an hour and no more.
     */
    public const string UNUSED_CLIENTS_EVERY = '1 hour';

    /**
     * What the retention of the journal is worth waiting for (issue #454): the duration it reads is months
     * long, a run is bounded and the next one takes what it left, so a day is short enough that a backlog
     * is worked through and long enough that a deployment with nothing to forget reads its journal once a
     * day and no more.
     */
    public const string JOURNAL_RETENTION_EVERY = '1 day';

    /**
     * What forgetting an expired archive is worth waiting for (issue #453). An hour and not a day, where
     * the journal waits a day: an archive is the one file in which everything this provider knows of a
     * person stands in clear at once, so the window between the moment it is worth nothing and the moment
     * it is gone is the one window this schedule keeps short.
     */
    public const string EXPIRED_ARCHIVES_EVERY = '1 hour';

    /**
     * What the retention of the history of a record is worth waiting for (issue #482): the same day the
     * journal waits, a change and the act that announced it being two halves of one answer and read
     * together.
     */
    public const string HISTORY_RETENTION_EVERY = '1 day';

    /**
     * What the databases of addresses are worth waiting for (issue #473): MaxMind publishes GeoLite2 once
     * a week, so a week is the cadence of what is being followed and not a guess. A week in which nothing
     * was published costs one request and no download, the ETag of what is stored going out with it, and a
     * deployment that names no licence key downloads nothing at all.
     */
    public const string ADDRESS_DATABASES_EVERY = '1 week';

    /**
     * What dropping the rows that can no longer do anything is worth waiting for (issue #177). An hour and
     * not a minute, although the shortest-lived of them is worth nothing sixty seconds after it was
     * written: none of it is readable where it sits, every column of a person in these tables being sealed
     * (decision 0011), so what the wait costs is rows and not exposure, and the rows are small. Every
     * statement it makes is bounded and the next run takes what it left, so an hour is short enough that a
     * backlog is worked through at the rate a client can post.
     */
    public const string DEAD_RECORDS_EVERY = '1 hour';

    /**
     * What the metadata of the SAML peers are worth waiting for, the service providers and the upstream identity
     * providers (beffroi/saml, spec/saml.md sections 6.2 and 6.10): a peer that publishes a new key publishes it ahead
     * of using it, and an hour is short enough that it is read before then, long enough that a deployment with nothing
     * new costs one request per peer and no write. `cacheDuration` is not read: how long to keep a document is this provider's to say (model.md section
     * 6.5 step 3), and a document refused leaves the accepted one serving until its own validUntil.
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
