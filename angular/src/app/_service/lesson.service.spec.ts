import { LessonService } from './lesson.service';
import {TestBed} from "@angular/core/testing";

describe('LessonService', () => {
  let service: LessonService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(LessonService);
  });

  it('should create an instance', () => {
    expect(service).toBeTruthy();
  });
});
