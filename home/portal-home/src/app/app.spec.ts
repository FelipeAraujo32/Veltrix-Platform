import { provideHttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { App } from './app';

describe('App', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideRouter([]), provideHttpClient()],
    }).compileComponents();
  });

  it('should create the app', () => {
    expect(TestBed.createComponent(App).componentInstance).toBeTruthy();
  });

  it('should render the accessible product name', async () => {
    const fixture = TestBed.createComponent(App);
    await fixture.whenStable();
    const compiled = fixture.nativeElement as HTMLElement;
    // A marca no topbar é imagem: o nome acessível fica no alt (não em textContent).
    expect(compiled.querySelector('.brand img')?.getAttribute('alt')).toContain('Veltrix');
    expect(compiled.querySelector('.skip-link')?.textContent).toContain('conteúdo principal');
  });
});
