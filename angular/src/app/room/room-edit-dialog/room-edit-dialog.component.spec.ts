import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { RoomEditDialogComponent } from './room-edit-dialog.component';

describe('RoomEditDialogComponent', () => {
  let component: RoomEditDialogComponent;
  let fixture: ComponentFixture<RoomEditDialogComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ RoomEditDialogComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(RoomEditDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
