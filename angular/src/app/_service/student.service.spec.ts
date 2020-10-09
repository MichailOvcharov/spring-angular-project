import { TestBed } from '@angular/core/testing';

import { StudentService } from './student.service';
import {RoomService} from "./room.service";

describe('StudentService', () => {
  let service: StudentService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(StudentService);
  });

  it('should create an instance', () => {
    expect(service).toBeTruthy();
  });
});
