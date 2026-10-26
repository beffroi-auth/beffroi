<?php

declare(strict_types=1);

namespace App\Form;

use Beffroi\Core\Domain\Identity\Claim\ClaimField;
use Beffroi\Core\Domain\Identity\Claim\ClaimInterface;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\Form\FormView;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * One claim of a person, edited on its own (issue beffroi-auth/op#17): one field, one button, one line of
 * the page. A form per claim and not one form for all of them, because what this page does is let somebody
 * correct one thing where they read it, and a single form would make them save thirteen others to do it.
 *
 * What kind of field it is, the claim says (beffroi-auth/beffroi#476); what type that is, ClaimFieldTypes
 * maps. Nothing here knows the claims by name.
 *
 * The field comes from ClaimForms and is not read off the claim here, because which field a claim is
 * offered as depends on what is already held: a birthdate held as a year alone is a line of text and not a
 * calendar, a calendar rendering it empty and a save on an empty field erasing it
 * (beffroi-auth/beffroi#479).
 */
final class ClaimType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $claim = $options['claim'];
        $field = $options['field'];
        $builder->add('value', ClaimFieldTypes::of($field), ClaimFieldTypes::optionsOf($field, $claim->name()));
    }

    /**
     * The page renders the suggestions of a set of several hundred beside the field, no type of the
     * component producing a `<datalist>` (beffroi-auth/beffroi#479), so the view carries the field this form
     * was built for and the page reads it there rather than being handed a second list beside the forms.
     */
    public function buildView(FormView $view, FormInterface $form, array $options): void
    {
        $view->vars['field'] = $options['field'];
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setRequired(['claim', 'field']);
        $resolver->setAllowedTypes('claim', ClaimInterface::class);
        $resolver->setAllowedTypes('field', ClaimField::class);
        // nothing else is set: the token id is the one of config/packages/csrf.yaml, which is the stateless
        // protection the form component is installed with here
    }
}
