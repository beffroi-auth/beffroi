<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Doctrine\ORM\QueryBuilder;

/**
 * What a column of authors holds for the authors of one kind (`WrittenAuthorType::rowsOfKind()`), as the condition a
 * listing narrows itself by.
 */
final readonly class RowsOfAKind
{
    /**
     * @param string      $documents    a pattern of LIKE the documents of the kind match
     * @param string|null $notADocument a pattern of LIKE every document matches, when a bare subject a row written before holds is of the kind
     * @param bool        $nothing      whether a row that holds NULL is of the kind
     */
    public function __construct(
        public string $documents,
        public ?string $notADocument,
        public bool $nothing,
    ) {
    }

    public function narrow(QueryBuilder $query, string $field): void
    {
        $expression = $query->expr();
        $conditions = [$field . ' LIKE :author_documents'];
        $query->setParameter('author_documents', $this->documents);
        if ($this->notADocument !== null) {
            $conditions[] = $expression->andX($field . ' IS NOT NULL', $field . ' NOT LIKE :author_not_a_document');
            $query->setParameter('author_not_a_document', $this->notADocument);
        }
        if ($this->nothing) {
            $conditions[] = $field . ' IS NULL';
        }
        $query->andWhere($expression->orX(...$conditions));
    }
}
