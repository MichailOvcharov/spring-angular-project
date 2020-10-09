export class PageParams {
  start:number;
  page:number;
  params;

  constructor(start:number, page:number, params){
    this.start = start;
    this.page = page;
    this.params = params;
  }
}
