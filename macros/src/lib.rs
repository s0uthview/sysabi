//! Proc-macros for `sysabi`. Use it through the `sysabi` crate.
//!
//! The `kernel` and `user` features select which halves are generated.

use std::collections::HashMap;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    Attribute, Error, Expr, ExprLit, FnArg, Ident, ItemTrait, Lit, LitInt, LitStr, Meta,
    MetaNameValue, Pat, ReturnType, Token, TraitItem, Type, Visibility, parse_macro_input,
};

const MAX_ARGS: usize = 6;

#[proc_macro_attribute]
pub fn abi(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemTrait);

    match expand(attr.into(), item) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

struct AbiArgs {
    name: LitStr,
    version: u32,
    errno: Type,
    module: Option<Ident>,
}

struct Syscall {
    attrs: Vec<Attribute>,
    name: Ident,
    nr: usize,
    since: u32,
    is_unsafe: bool,
    args: Vec<(Ident, Type)>,
    ret: Type,
    ret_str: String,
}

fn expand(attr: TokenStream2, item: ItemTrait) -> syn::Result<TokenStream2> {
    let abi = parse_abi_args(attr)?;

    if !item.generics.params.is_empty() || item.generics.where_clause.is_some() {
        return Err(Error::new(
            item.generics.span(),
            "generics are not allowed on ABI traits",
        ));
    }

    if !item.supertraits.is_empty() {
        return Err(Error::new(
            item.supertraits.span(),
            "supertraits are not allowed on ABI traits",
        ));
    }

    let mut errors: Option<Error> = None;
    let mut push_err = |e: Error| match &mut errors {
        Some(errs) => errs.combine(e),
        None => errors = Some(e),
    };
    let mut syscalls = Vec::new();

    for ti in &item.items {
        match parse_syscall(ti, &abi) {
            Ok(sc) => syscalls.push(sc),
            Err(e) => push_err(e),
        }
    }

    let mut by_nr: HashMap<usize, &Ident> = HashMap::new();

    for sc in &syscalls {
        if let Some(prev) = by_nr.insert(sc.nr, &sc.name) {
            push_err(Error::new(
                sc.name.span(),
                format!("syscall number {} is already used by `{prev}`", sc.nr),
            ));
        }
    }

    if let Some(e) = errors {
        return Err(e);
    }

    Ok(generate(&abi, &item, &syscalls))
}

fn parse_abi_args(attr: TokenStream2) -> syn::Result<AbiArgs> {
    let metas = Punctuated::<MetaNameValue, Token![,]>::parse_terminated.parse2(attr)?;

    let mut name = None;
    let mut version = None;
    let mut errno = None;
    let mut module = None;

    for mnv in &metas {
        let key = mnv
            .path
            .get_ident()
            .map(Ident::to_string)
            .unwrap_or_default();
        let dup = |set: bool| {
            if set {
                Err(Error::new(mnv.path.span(), format!("duplicate `{key}`")))
            } else {
                Ok(())
            }
        };

        match key.as_str() {
            "abi" => {
                dup(name.is_some())?;

                name = Some(expect_str(&mnv.value)?);
            }
            "version" => {
                dup(version.is_some())?;

                let v: u32 = expect_int(&mnv.value)?.base10_parse()?;

                if v == 0 {
                    return Err(Error::new(mnv.value.span(), "`version` must be non-zero"));
                }

                version = Some(v);
            }
            "errno" => {
                dup(errno.is_some())?;

                errno = Some(syn::parse2::<Type>(value_tokens(&mnv.value))?);
            }
            "module" => {
                dup(module.is_some())?;

                module = Some(syn::parse2::<Ident>(value_tokens(&mnv.value))?);
            }
            _ => {
                return Err(Error::new(
                    mnv.path.span(),
                    "unknown ABI property; expected `abi`, `version`, `errno` or `module`",
                ));
            }
        }
    }

    let missing = |what: &str| {
        Error::new(
            Span::call_site(),
            format!("missing `{what} = ...` in #[sysabi::abi(...)]"),
        )
    };

    Ok(AbiArgs {
        name: name.ok_or_else(|| missing("abi"))?,
        version: version.ok_or_else(|| missing("abi"))?,
        errno: errno.ok_or_else(|| missing("errno"))?,
        module,
    })
}

fn value_tokens(e: &Expr) -> TokenStream2 {
    quote!(#e)
}

fn expect_str(e: &Expr) -> syn::Result<LitStr> {
    match e {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => Ok(s.clone()),
        _ => Err(Error::new(e.span(), "expected string literal")),
    }
}

fn expect_int(e: &Expr) -> syn::Result<LitInt> {
    match e {
        Expr::Lit(ExprLit {
            lit: Lit::Int(i), ..
        }) => Ok(i.clone()),
        _ => Err(Error::new(e.span(), "expected integer literal")),
    }
}

fn parse_syscall(ti: &TraitItem, abi: &AbiArgs) -> syn::Result<Syscall> {
    let TraitItem::Fn(f) = ti else {
        return Err(Error::new(
            ti.span(),
            "only syscall decls (`fn`) are allowed here",
        ));
    };

    let sig = &f.sig;

    if let Some(body) = &f.default {
        return Err(Error::new(
            body.span(),
            "syscall declarations cannot have a default implementation",
        ));
    }

    if !sig.generics.params.is_empty() || sig.generics.where_clause.is_some() {
        return Err(Error::new(
            sig.generics.span(),
            "syscalls cannot be generic",
        ));
    }

    if let Some(t) = sig
        .constness
        .as_ref()
        .map(Spanned::span)
        .or(sig.asyncness.as_ref().map(Spanned::span))
        .or(sig.abi.as_ref().map(Spanned::span))
        .or(sig.variadic.as_ref().map(Spanned::span))
    {
        return Err(Error::new(t, "syscalls must be `fn` or `unsafe fn`"));
    }

    let mut nr = None;
    let mut since = None;
    let mut attrs = Vec::new();

    for attr in &f.attrs {
        if !attr.path().is_ident("syscall") {
            attrs.push(attr.clone());

            continue;
        }

        let Meta::List(list) = &attr.meta else {
            return Err(Error::new(attr.span(), "expected #[syscall(nr = ...)]"));
        };
        let metas =
            list.parse_args_with(Punctuated::<MetaNameValue, Token![,]>::parse_terminated)?;

        for mnv in &metas {
            if mnv.path.is_ident("nr") {
                nr = Some(expect_int(&mnv.value)?.base10_parse::<usize>()?);
            } else if mnv.path.is_ident("since") {
                let lit = expect_int(&mnv.value)?;
                let v = lit.base10_parse::<u32>()?;

                if v == 0 || v > abi.version {
                    return Err(Error::new(
                        lit.span(),
                        format!("`since` must be in 1..={} (abi vers)", abi.version),
                    ));
                }

                since = Some(v);
            } else {
                return Err(Error::new(mnv.path.span(), "expected `nr` or `since`"));
            }
        }
    }

    let nr = nr.ok_or_else(|| {
        Error::new(
            sig.ident.span(),
            "missing #[syscall(nr = ...)] on syscall decl",
        )
    })?;

    let mut args = Vec::new();

    for input in &sig.inputs {
        match input {
            FnArg::Receiver(r) => {
                return Err(Error::new(
                    r.span(),
                    "syscall decls take no `self`; the kernel handler gets `&self` added",
                ));
            }
            FnArg::Typed(pt) => {
                let Pat::Ident(pi) = &*pt.pat else {
                    return Err(Error::new(
                        pt.pat.span(),
                        "syscall arguments must be plain idents",
                    ));
                };

                args.push((pi.ident.clone(), (*pt.ty).clone()));
            }
        }
    }

    if args.len() > MAX_ARGS {
        return Err(Error::new(
            sig.inputs.span(),
            format!(
                "syscalls can have up to {MAX_ARGS} args, found {}",
                args.len()
            ),
        ));
    }

    let ret: Type = match &sig.output {
        ReturnType::Default => syn::parse_quote!(()),
        ReturnType::Type(_, ty) => match &**ty {
            Type::Never(_) => syn::parse_quote!(::core::convert::Infallible),
            ty => ty.clone(),
        },
    };

    let ret_str = match &sig.output {
        ReturnType::Default => "()".to_owned(),
        ReturnType::Type(_, ty) => type_string(ty),
    };

    Ok(Syscall {
        attrs,
        name: sig.ident.clone(),
        nr,
        since: since.unwrap_or(1),
        is_unsafe: sig.unsafety.is_some(),
        args,
        ret,
        ret_str,
    })
}

fn type_string(ty: &Type) -> String {
    // collapse token-stream spacing (`* const u8`) into something human-readable
    let s = quote!(#ty).to_string();

    s.replace(" < ", "<")
        .replace(" <", "<")
        .replace("< ", "<")
        .replace(" >", ">")
        .replace(" ,", ",")
        .replace("& ", "&")
        .replace("* ", "*")
        .replace(" :: ", "::")
}

fn snake_case(s: &str) -> String {
    let mut out = String::new();

    for (i, c) in s.char_indices() {
        if c.is_uppercase() {
            let prev_lower = s[..i]
                .chars()
                .last()
                .is_some_and(|p| p.is_lowercase() || p.is_ascii_digit());

            if prev_lower {
                out.push('_');
            }

            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }

    out
}

fn generate(abi: &AbiArgs, item: &ItemTrait, syscalls: &[Syscall]) -> TokenStream2 {
    let vis = &item.vis;
    let trait_name = &item.ident;
    let module = abi
        .module
        .clone()
        .unwrap_or_else(|| Ident::new(&snake_case(&trait_name.to_string()), trait_name.span()));
    let abi_name = &abi.name;
    let version = abi.version;

    let nr_consts = syscalls.iter().map(|sc| {
        let konst = nr_const(sc);
        let nr = sc.nr;
        let doc = format!("`{}`", sc.name);
        quote!(#[doc = #doc] pub const #konst: usize = #nr;)
    });

    let descs = syscalls.iter().map(|sc| {
        let name = sc.name.to_string();
        let nr = sc.nr;
        let since = sc.since;
        let ret = &sc.ret_str;
        let is_unsafe = sc.is_unsafe;
        let args = sc.args.iter().map(|(n, t)| {
            let n = n.to_string();
            let t = type_string(t);
            quote!(::sysabi::ArgDesc { name: #n, ty: #t })
        });
        quote! {
            ::sysabi::SyscallDesc {
                name: #name, nr: #nr, since: #since, args: &[#(#args),*],
                ret: #ret, is_unsafe: #is_unsafe,
            }
        }
    });

    let lookup_arms = syscalls.iter().enumerate().map(|(i, sc)| {
        let konst = nr_const(sc);
        quote!(nr::#konst => ::core::option::Option::Some(&SYSCALLS[#i]),)
    });

    let kernel_trait = cfg!(feature = "kernel").then(|| kernel_trait(abi, item, syscalls));
    let kernel_mod = cfg!(feature = "kernel").then(|| kernel_mod(abi, item, syscalls));
    let user_mod = cfg!(feature = "user").then(|| user_mod(abi, syscalls));

    let mod_doc = format!("The `{}` syscall ABI, version {version}.", abi.name.value());
    let mod_vis = match vis {
        Visibility::Inherited => quote!(pub(super)),
        v => quote!(#v),
    };

    quote! {
        #kernel_trait

        #[doc = #mod_doc]
        #mod_vis mod #module {
            #[allow(unused_imports)]
            use super::*;

            pub static ABI: ::sysabi::AbiDesc = ::sysabi::AbiDesc { name: #abi_name, version: #version };

            /// Syscall numbers.
            pub mod nr {
                #(#nr_consts)*
            }

            /// Descriptions of the syscalls in the ABI, in order of declaration.
            pub static SYSCALLS: &[::sysabi::SyscallDesc] = &[#(#descs),*];

            /// Look up a syscall by its number.
            pub fn lookup(nr: usize) -> ::core::option::Option<&'static ::sysabi::SyscallDesc> {
                match nr {
                    #(#lookup_arms)*
                    _ => ::core::option::Option::None,
                }
            }

            #kernel_mod
            #user_mod
        }
    }
}

fn nr_const(sc: &Syscall) -> Ident {
    format_ident!(
        "{}",
        sc.name.to_string().to_uppercase(),
        span = sc.name.span()
    )
}

fn kernel_trait(abi: &AbiArgs, item: &ItemTrait, syscalls: &[Syscall]) -> TokenStream2 {
    let attrs = &item.attrs;
    let vis = &item.vis;
    let name = &item.ident;
    let errno = &abi.errno;

    let methods = syscalls.iter().map(|sc| {
        let attrs = &sc.attrs;
        let fname = &sc.name;
        let ret = &sc.ret;
        let cx = if sc.args.iter().any(|(n, _)| n == "cx") {
            format_ident!("__cx")
        } else {
            format_ident!("cx")
        };
        let args = sc.args.iter().map(|(n, t)| quote!(#n: #t));

        quote! {
            #(#attrs)*
            fn #fname(&self, #cx: &mut Self::Context, #(#args),*) -> ::core::result::Result<#ret, #errno>;
        }
    });

    quote! {
        #(#attrs)*
        #vis trait #name {
            /// Per-call kernel state passed to the handler + hooks, usually the
            /// calling thread or process.
            type Context: ?::core::marker::Sized;

            #(#methods)*
        }
    }
}

fn kernel_mod(abi: &AbiArgs, item: &ItemTrait, syscalls: &[Syscall]) -> TokenStream2 {
    let trait_name = &item.ident;
    let errno = &abi.errno;
    let max = MAX_ARGS;
    let arms = syscalls.iter().map(|sc| {
        let konst = nr_const(sc);
        let fname = &sc.name;
        let ret = &sc.ret;
        let locals: Vec<Ident> = (0..sc.args.len()).map(|i| format_ident!("__a{i}")).collect();
        let decode = sc
            .args
            .iter()
            .zip(&locals)
            .enumerate()
            .map(|(i, ((_, ty), local))| {
                quote! {
                    let #local = match <#ty as ::sysabi::SyscallArg>::from_raw(args[#i]) {
                        ::core::option::Option::Some(v) => v,
                        ::core::option::Option::None => {
                            return ::core::result::Result::Err(<#errno as ::sysabi::ErrorCode>::INVAL);
                        }
                    };
                }
            });

        quote! {
            super::nr::#konst => {
                #(#decode)*
                handler.#fname(cx, #(#locals),*).map(<#ret as ::sysabi::SyscallArg>::into_raw)
            }
        }
    });

    quote! {
        /// The kernel half of the ABI.
        pub mod kernel {
            #[allow(unused_imports)]
            use super::*;

            /// Handle a syscall trap, returning the value for the return register.
            ///
            /// Runs `hooks.filter`, decodes the args, calls `handler`, then runs
            /// `hooks.on_return` with the return value.
            pub fn dispatch<H, K>(
                handler: &H,
                hooks: &K,
                cx: &mut H::Context,
                nr: usize,
                args: [usize; #max],
            ) -> usize
            where
                H: super::super::#trait_name + ?::core::marker::Sized,
                K: ::sysabi::Hooks<H::Context, #errno> + ?::core::marker::Sized,
            {
                let info = ::sysabi::SyscallInfo { abi: &super::ABI, nr, desc: super::lookup(nr), args };
                let ret = match hooks.filter(cx, &info) {
                    ::core::result::Result::Ok(()) => call(handler, cx, nr, &args),
                    ::core::result::Result::Err(e) => ::core::result::Result::Err(e),
                };

                hooks.on_return(cx, &info, &ret);

                ::sysabi::encode(ret)
            }

            #[inline]
            fn call<H>(
                handler: &H,
                cx: &mut H::Context,
                nr: usize,
                args: &[usize; #max],
            ) -> ::core::result::Result<usize, #errno>
            where
                H: super::super::#trait_name + ?::core::marker::Sized,
            {
                match nr {
                    #(#arms)*
                    _ => ::core::result::Result::Err(<#errno as ::sysabi::ErrorCode>::NOSYS),
                }
            }
        }
    }
}

fn user_mod(abi: &AbiArgs, syscalls: &[Syscall]) -> TokenStream2 {
    let errno = &abi.errno;

    let stubs = syscalls.iter().map(|sc| {
        let attrs = &sc.attrs;
        let fname = &sc.name;
        let ret = &sc.ret;
        let konst = nr_const(sc);
        let unsafety = sc.is_unsafe.then(|| quote!(unsafe));
        let params = sc.args.iter().map(|(n, t)| quote!(#n: #t));
        let raw_args = sc
            .args
            .iter()
            .map(|(n, t)| quote!(<#t as ::sysabi::SyscallArg>::into_raw(#n)));
        let trap = format_ident!("syscall{}", sc.args.len());

        quote! {
            #(#attrs)*
            #[inline]
            pub #unsafety fn #fname(#(#params),*) -> ::core::result::Result<#ret, #errno> {
                let __raw = unsafe { ::sysabi::arch::#trap(super::nr::#konst, #(#raw_args),*) };

                match ::sysabi::decode::<#errno>(__raw) {
                    ::core::result::Result::Ok(v) => <#ret as ::sysabi::SyscallArg>::from_raw(v)
                        .ok_or(<#errno as ::sysabi::ErrorCode>::INVAL),
                    ::core::result::Result::Err(e) => ::core::result::Result::Err(e),
                }
            }
        }
    });

    quote! {
        /// The user half of the ABI. Stubs that trap into the kernel.
        pub mod user {
            #[allow(unused_imports)]
            use super::*;

            #(#stubs)*
        }
    }
}
