<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use EasyCorp\Bundle\EasyAdminBundle\Attribute\AdminDashboard;
use EasyCorp\Bundle\EasyAdminBundle\Config\Dashboard;
use EasyCorp\Bundle\EasyAdminBundle\Config\MenuItem;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractDashboardController;
use Symfony\Component\HttpFoundation\Response;

/**
 * The back office: the list of leads, nothing else.
 */
#[AdminDashboard(routePath: '/admin', routeName: 'admin')]
final class DashboardController extends AbstractDashboardController
{
    public function index(): Response
    {
        return $this->redirectToRoute('admin_lead_index');
    }

    public function configureDashboard(): Dashboard
    {
        return Dashboard::new()->setTitle('Beffroi leads')->setFaviconPath('/favicon.svg')->disableDarkMode();
    }

    public function configureMenuItems(): iterable
    {
        yield MenuItem::linkTo(LeadCrudController::class, 'Leads', 'fa fa-address-book');
        yield MenuItem::linkToUrl('Website', 'fa fa-globe', '/');
    }
}
