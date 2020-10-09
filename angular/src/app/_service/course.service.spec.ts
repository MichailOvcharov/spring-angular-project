import { CourseService } from './course.service';
import {InstrumentService} from "./instrument.service";
import {TestBed} from "@angular/core/testing";

describe('CourseService', () => {
  let service: CourseService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(CourseService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
