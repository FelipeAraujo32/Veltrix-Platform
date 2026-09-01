import { Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthService } from '@veltrix/shared-client/services/auth.service';

@Component({
  selector: 'app-sobre',
  imports: [RouterLink],
  templateUrl: './sobre.html',
  styleUrl: './sobre.scss',
})
export class Sobre {
  protected readonly auth = inject(AuthService);
}
