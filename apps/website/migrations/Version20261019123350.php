<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261019123350 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'What Sweego reports of the confirmation of a lead: delivered, opened, clicked, bounced, reported as spam, unsubscribed';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('ALTER TABLE lead ADD confirmation_delivered_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL');
        $this->addSql('ALTER TABLE lead ADD confirmation_opened_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL');
        $this->addSql('ALTER TABLE lead ADD confirmation_clicked_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL');
        $this->addSql('ALTER TABLE lead ADD confirmation_bounced_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL');
        $this->addSql('ALTER TABLE lead ADD marked_as_spam_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL');
        $this->addSql('ALTER TABLE lead ADD unsubscribed_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('ALTER TABLE lead DROP confirmation_delivered_at');
        $this->addSql('ALTER TABLE lead DROP confirmation_opened_at');
        $this->addSql('ALTER TABLE lead DROP confirmation_clicked_at');
        $this->addSql('ALTER TABLE lead DROP confirmation_bounced_at');
        $this->addSql('ALTER TABLE lead DROP marked_as_spam_at');
        $this->addSql('ALTER TABLE lead DROP unsubscribed_at');
    }
}
