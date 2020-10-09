import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { StudentEditDialogComponent } from './student-edit-dialog.component';

describe('StudentEditDialogComponent', () => {
  let component: StudentEditDialogComponent;
  let fixture: ComponentFixture<StudentEditDialogComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ StudentEditDialogComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(StudentEditDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
