<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Session;

enum SessionOutcome: string {
    case RESTORED = 'restored';
    case CREATED = 'created';
}
