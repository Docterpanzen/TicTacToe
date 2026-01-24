import { Routes } from '@angular/router';
import { LoginComponent } from './auth/login';
import { Tictactoe } from './tictactoe/tictactoe';

export const routes: Routes = [
	{ path: '', pathMatch: 'full', redirectTo: 'local' },
	{ path: 'login', component: LoginComponent },
	{ path: 'local', component: Tictactoe },
	{ path: '**', redirectTo: 'local' },
];
