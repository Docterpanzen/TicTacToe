import { Component } from '@angular/core';
import { Tictactoe } from './tictactoe/tictactoe';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [Tictactoe, Tictactoe],
  templateUrl: './app.html',
  styleUrls: ['./app.scss'],
})
export class App {
  title = 'TicTacToe';
}
