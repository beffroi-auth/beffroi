<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * beffroi/saml S-51, S-61: a sign-on at an upstream identity provider started as a person starts it, from the step of
 * the address of the login page, posted under its form token, the browser sent to the sign-on of the provider of that
 * domain under the one-time reference the step drew; a sign-on reached any other way starts nothing.
 */
trait SignOnFromTheLoginPage
{
    /**
     * The address typed at the step of the address of the login page of that interaction, or of the login a page of
     * the provider waits for when there is none, and posted: the browser is sent to the sign-on of its provider.
     */
    private function typeTheAddress(?string $interaction, string $address): void
    {
        $form = $this->browser
            ->request(
                'GET',
                '/login',
                $interaction === null
                    ? []
                    : [
                        'interaction' => $interaction,
                    ],
            )
            ->filter('form[data-step="address"]')
            ->form();
        $form['_address'] = $address;
        $this->browser->submit($form);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode(), self::string($response->getContent()));
    }

    /**
     * The address typed and posted, and the redirection to the sign-on followed: the answer of the sign-on.
     */
    private function signOnAs(?string $interaction, string $address): Crawler
    {
        $this->typeTheAddress($interaction, $address);

        return $this->browser->followRedirect();
    }
}
