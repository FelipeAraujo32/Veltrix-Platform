import { Component,inject,signal } from '@angular/core';
import { FormBuilder,ReactiveFormsModule,Validators } from '@angular/forms';
import { ActivatedRoute,Router,RouterLink } from '@angular/router';
import { finalize,switchMap } from 'rxjs';
import { AuthService } from '@veltrix/shared-client/services/auth.service';
import { RuntimeConfigService } from '@veltrix/shared-client/services/runtime-config.service';

@Component({selector:'app-login',imports:[ReactiveFormsModule,RouterLink],templateUrl:'./login.html',styleUrl:'./login.scss'})
export class Login {
 private readonly auth=inject(AuthService);private readonly runtime=inject(RuntimeConfigService);private readonly fb=inject(FormBuilder);private readonly router=inject(Router);private readonly route=inject(ActivatedRoute);
 readonly loading=signal(false);readonly error=signal('');
 readonly form=this.fb.nonNullable.group({email:['',[Validators.required,Validators.email]],password:['',Validators.required]});
 submit():void{if(this.form.invalid){this.form.markAllAsTouched();return;}this.loading.set(true);this.error.set('');const value=this.form.getRawValue();this.auth.login(value.email,value.password).pipe(switchMap(()=>this.auth.loadCurrentUser()),finalize(()=>this.loading.set(false))).subscribe({next:()=>this.redirectAfterLogin(),error:e=>this.error.set(e.friendlyMessage||'E-mail ou senha inválidos.')});}
 private redirectAfterLogin():void{const target=this.route.snapshot.queryParamMap.get('returnUrl');if(!target){void this.router.navigateByUrl('/apps');return;}if(target.startsWith('/')&&!target.startsWith('//')&&!target.includes('\\')){void this.router.navigateByUrl(target);return;}try{const url=new URL(target);if(url.username||url.password)throw new Error('Credentials are not allowed in return URLs');const allowedOrigins=new Set([location.origin]);for(const base of Object.values(this.runtime.moduleBaseUrls)){try{allowedOrigins.add(new URL(base).origin);}catch{}}if(allowedOrigins.has(url.origin)){location.assign(url.toString());return;}}catch{}void this.router.navigateByUrl('/apps');}
}
