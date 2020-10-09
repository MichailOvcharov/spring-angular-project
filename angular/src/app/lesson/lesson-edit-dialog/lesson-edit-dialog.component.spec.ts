import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { LessonEditDialogComponent } from './lesson-edit-dialog.component';

describe('LessonEditDialogComponent', () => {
  let component: LessonEditDialogComponent;
  let fixture: ComponentFixture<LessonEditDialogComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ LessonEditDialogComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(LessonEditDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
