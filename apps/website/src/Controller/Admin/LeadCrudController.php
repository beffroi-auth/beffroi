<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use RuntimeException;
use App\Entity\Lead;
use App\Lead\LeadStatus;
use App\Lead\OidcProvider;
use App\Repository\LeadRepository;
use EasyCorp\Bundle\EasyAdminBundle\Attribute\AdminRoute;
use EasyCorp\Bundle\EasyAdminBundle\Config\Action;
use EasyCorp\Bundle\EasyAdminBundle\Config\Actions;
use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;
use EasyCorp\Bundle\EasyAdminBundle\Config\Filters;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\ChoiceField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\EmailField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextareaField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use Symfony\Component\HttpFoundation\HeaderUtils;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * The leads. What the visitor gave is shown and never edited; the status and the notes are edited here, and deleting
 * a lead is how a request for erasure is honoured. Leads are created by the sign-up form only.
 *
 * @extends AbstractCrudController<Lead>
 */
final class LeadCrudController extends AbstractCrudController
{
    private const array CSV_COLUMNS = [
        'created_at',
        'first_name',
        'last_name',
        'company',
        'email',
        'provider',
        'provider_other',
        'source',
        'consented_at',
        'confirmation_sent_at',
        'status',
        'notes',
    ];

    public function __construct(
        private readonly LeadRepository $leads,
    ) {
    }

    public static function getEntityFqcn(): string
    {
        return Lead::class;
    }

    public function configureCrud(Crud $crud): Crud
    {
        return $crud
            ->setEntityLabelInSingular('Lead')
            ->setEntityLabelInPlural('Leads')
            ->setDefaultSort(['createdAt' => 'DESC'])
            ->setSearchFields(['email', 'firstName', 'lastName', 'company', 'providerOther', 'notes'])
            ->setPaginatorPageSize(50);
    }

    public function configureActions(Actions $actions): Actions
    {
        $export = Action::new('export', 'Export CSV', 'fa fa-file-csv')->linkToCrudAction('export')->createAsGlobalAction();

        return $actions->disable(Action::NEW)->add(Crud::PAGE_INDEX, Action::DETAIL)->add(Crud::PAGE_INDEX, $export);
    }

    public function configureFields(string $pageName): iterable
    {
        yield DateTimeField::new('createdAt', 'Signed up')->hideOnForm();
        yield TextField::new('firstName', 'First name')->hideOnForm();
        yield TextField::new('lastName', 'Last name')->hideOnForm();
        yield TextField::new('company')->hideOnForm();
        yield EmailField::new('email')->hideOnForm();
        yield ChoiceField::new('provider')->setChoices(OidcProvider::cases())->hideOnForm();
        yield TextField::new('providerOther', 'Other provider')->hideOnForm()->hideOnIndex();
        yield TextField::new('source')->hideOnForm()->hideOnIndex();
        yield DateTimeField::new('consentedAt', 'Consent given')->hideOnForm()->hideOnIndex();
        yield DateTimeField::new('confirmationSentAt', 'Confirmation sent')->hideOnForm()->hideOnIndex();
        yield ChoiceField::new('status')->setChoices(LeadStatus::cases())->renderAsBadges([
            LeadStatus::New->value => 'primary',
            LeadStatus::Contacted->value => 'info',
            LeadStatus::Interested->value => 'success',
            LeadStatus::NotInterested->value => 'secondary',
        ]);
        yield TextareaField::new('notes')->hideOnIndex()->setNumOfRows(8);
    }

    public function configureFilters(Filters $filters): Filters
    {
        return $filters->add('provider')->add('status')->add('createdAt');
    }

    /**
     * Every lead as CSV, UTF-8 with a byte order mark so that spreadsheets read the accents.
     */
    #[AdminRoute('/export', name: 'export', options: ['methods' => ['GET']])]
    public function export(): StreamedResponse
    {
        $response = new StreamedResponse(function (): void {
            $output = fopen('php://output', 'w');
            if (false === $output) {
                throw new RuntimeException('The output stream could not be opened.');
            }

            fwrite($output, "\u{FEFF}");
            fputcsv($output, self::CSV_COLUMNS, escape: '');
            foreach ($this->leads->streamNewestFirst() as $lead) {
                fputcsv(
                    $output,
                    [
                        $lead->createdAt->format(\DATE_ATOM),
                        $lead->firstName,
                        $lead->lastName,
                        $lead->company ?? '',
                        $lead->email,
                        $lead->provider->label(),
                        $lead->providerOther ?? '',
                        $lead->source,
                        $lead->consentedAt->format(\DATE_ATOM),
                        $lead->confirmationSentAt?->format(\DATE_ATOM) ?? '',
                        $lead->status->label(),
                        $lead->notes ?? '',
                    ],
                    escape: '',
                );
            }
            fclose($output);
        });

        $response->headers->set('Content-Type', 'text/csv; charset=utf-8');
        $response->headers->set('Content-Disposition', HeaderUtils::makeDisposition(
            HeaderUtils::DISPOSITION_ATTACHMENT,
            \sprintf('beffroi-leads-%s.csv', date('Y-m-d')),
        ));

        return $response;
    }
}
