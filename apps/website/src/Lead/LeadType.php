<?php

declare(strict_types=1);

namespace App\Lead;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\EnumType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * The sign-up form. The browser's own checks are off: the server says what is wrong, in the page's words.
 *
 * @extends AbstractType<LeadRequest>
 */
final class LeadType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('firstName', TextType::class, [
                'label' => 'First name',
                'attr' => ['autocomplete' => 'given-name', 'maxlength' => 100],
            ])
            ->add('lastName', TextType::class, [
                'label' => 'Last name',
                'attr' => ['autocomplete' => 'family-name', 'maxlength' => 100],
            ])
            ->add('company', TextType::class, [
                'label' => 'Company',
                'required' => false,
                'attr' => ['autocomplete' => 'organization', 'maxlength' => 150],
            ])
            ->add('email', EmailType::class, [
                'label' => 'Email',
                'attr' => ['autocomplete' => 'email', 'maxlength' => 180, 'spellcheck' => 'false'],
            ])
            ->add('provider', EnumType::class, [
                'class' => OidcProvider::class,
                'label' => 'Which OpenID Connect provider do you use today?',
                'placeholder' => 'Choose one',
            ])
            ->add('providerOther', TextType::class, [
                'label' => 'Which one?',
                'required' => false,
                'attr' => ['maxlength' => 100],
            ])
            ->add('consent', CheckboxType::class, [
                'label' => 'I agree to receive a confirmation email now, and an email when Beffroi is released.',
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => LeadRequest::class,
            'attr' => ['novalidate' => 'novalidate'],
        ]);
    }

    public function getBlockPrefix(): string
    {
        return 'signup';
    }
}
