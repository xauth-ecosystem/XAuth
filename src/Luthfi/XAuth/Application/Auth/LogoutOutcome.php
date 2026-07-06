<?php

declare(strict_types=1);

namespace Luthfi\XAuth\Application\Auth;

enum LogoutOutcome: string {
    case EXISTING_USER = 'existing_user';
    case NEW_USER = 'new_user';
}
