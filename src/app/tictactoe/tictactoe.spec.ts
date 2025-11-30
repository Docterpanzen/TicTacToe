import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Tictactoe } from './tictactoe';

describe('Tictactoe', () => {
  let component: Tictactoe;
  let fixture: ComponentFixture<Tictactoe>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Tictactoe]
    })
    .compileComponents();

    fixture = TestBed.createComponent(Tictactoe);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
