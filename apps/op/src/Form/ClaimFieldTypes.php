<?php

declare(strict_types=1);

namespace App\Form;

use function array_keys;
use Beffroi\Core\Domain\Identity\Claim\ClaimField;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\DateType;
use Symfony\Component\Form\Extension\Core\Type\TelType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Extension\Core\Type\UrlType;
use function sprintf;

/**
 * The form type a claim of the provider is edited with (issue beffroi-auth/op#17): the one place the kinds
 * a claim may be are mapped onto the types of symfony/form.
 *
 * The bundle says what a claim is and never what a form is: its own pages are bare HTML with a form token,
 * which is what lets this application dress them by one layout override (architecture §5.2). So the
 * mapping lives here, in the deployment that chose the component, and a kind the bundle adds is a line
 * here and nothing else.
 *
 * A closed set short enough to read is a choice of its values; a set of several hundred is typed into with
 * the whole set suggested, which is a line of text and a `<datalist>` the page renders beside it, there
 * being no type of the component for one and no script on these pages to grow one; anything else is typed
 * into the type its kind names, with what the browser may check before anything is sent carried on the
 * attributes.
 */
final readonly class ClaimFieldTypes
{
    /**
     * @return class-string
     */
    public static function of(ClaimField $field): string
    {
        if ($field->isPicked()) {
            return TextType::class;
        }
        if ($field->choices !== []) {
            return ChoiceType::class;
        }

        return match ($field->kind) {
            'tel' => TelType::class,
            'url' => UrlType::class,
            'date' => DateType::class,
            default => TextType::class,
        };
    }

    /**
     * @param string $claim the name the claim gives itself, which the label and the identifier of the
     *                      suggestions are both made of
     *
     * @return array<string, mixed>
     */
    public static function optionsOf(ClaimField $field, string $claim): array
    {
        $options = [
            'label' => 'profile.' . $claim,
            'required' => false,
            'translation_domain' => 'beffroi',
        ];
        if ($field->isPicked()) {
            return $options + [
                'attr' => [
                    'autocomplete' => 'off',
                    'list' => self::suggestions($claim),
                ],
            ];
        }
        if ($field->choices !== []) {
            return $options + [
                // a flat list with the label read beside it, and not the labels as keys: two values may
                // read the same and would be one choice if the label were the key
                'choices' => array_keys($field->choices),
                'choice_label' => static fn (string $value): string => $field->choices[$value] ?? $value,
                'placeholder' => 'profile.nothing',
                'choice_translation_domain' => false,
            ];
        }
        $attributes = [
            'autocomplete' => 'off',
        ];
        if ($field->pattern !== null) {
            $attributes['pattern'] = $field->pattern;
        }
        if ($field->kind === 'date') {
            return $options + [
                'widget' => 'single_text',
                'input' => 'string',
                'input_format' => 'Y-m-d',
                'html5' => true,
                'attr' => $attributes,
            ];
        }

        return $options + [
            'attr' => $attributes,
            // the example is a key of the catalogue of the bundle, as every word of these pages is
            'help' => $field->example,
            'help_translation_parameters' => [],
        ];
    }

    /**
     * The identifier the field and its `<datalist>` are joined by.
     */
    public static function suggestions(string $claim): string
    {
        return sprintf('claim-%s-values', $claim);
    }
}
