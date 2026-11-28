<?php

declare(strict_types=1);

namespace Beffroi\Core\Port;

interface KindsOfAuthorInterface
{
    /**
     * @return list<non-empty-string> the names the wired kinds of author give themselves, in the order they are wired
     */
    public function kinds(): array;
}
