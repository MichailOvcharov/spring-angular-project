import { TeacherService } from './teacher.service';
import {TestBed} from "@angular/core/testing";

describe('TeacherService', () => {
  let service: TeacherService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(TeacherService);
  });

  it('should create an instance', () => {
    expect(service).toBeTruthy();
  });
});
