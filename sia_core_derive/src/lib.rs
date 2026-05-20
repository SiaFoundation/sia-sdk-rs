use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, ItemFn, parse_macro_input};

/// Attribute macro for tests that run on both native and `wasm32`.
///
/// - Async fns get `#[tokio::test]` on native; on wasm the body is wrapped in
///   a `tokio::task::LocalSet` so the test can use `tokio::task::spawn_local`.
/// - Sync fns get the built-in `#[test]` on native.
/// - Both flavors get `#[wasm_bindgen_test]` on wasm32.
#[proc_macro_attribute]
pub fn cross_target_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let attrs = &input.attrs;
    let vis = &input.vis;
    let sig = &input.sig;
    let block = &input.block;

    let expanded = if sig.asyncness.is_some() {
        quote! {
            #[cfg(not(target_arch = "wasm32"))]
            #[::tokio::test]
            #(#attrs)*
            #vis #sig #block

            #[cfg(target_arch = "wasm32")]
            #[::wasm_bindgen_test::wasm_bindgen_test]
            #(#attrs)*
            #vis #sig {
                ::tokio::task::LocalSet::new().run_until(async move #block).await
            }
        }
    } else {
        quote! {
            #[cfg_attr(not(target_arch = "wasm32"), test)]
            #[cfg_attr(target_arch = "wasm32", ::wasm_bindgen_test::wasm_bindgen_test)]
            #(#attrs)*
            #vis #sig #block
        }
    };
    TokenStream::from(expanded)
}

#[proc_macro_derive(SiaEncode)]
pub fn derive_sia_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let (length_impl, encode_impl) = match &input.data {
        Data::Struct(data) => {
            let (lengths, encodes) = match &data.fields {
                Fields::Named(fields) => {
                    let lengths = fields.named.iter().filter_map(|f| match f.vis {
                        syn::Visibility::Public(_) => {
                            let name = &f.ident;
                            Some(quote! { len += self.#name.encoded_length(); })
                        }
                        _ => None,
                    });
                    let encodes = fields.named.iter().filter_map(|f| match f.vis {
                        syn::Visibility::Public(_) => {
                            let name = &f.ident;
                            Some(quote! { self.#name.encode(w)?; })
                        }
                        _ => None,
                    });
                    (quote! { #(#lengths)* }, quote! { #(#encodes)* })
                }
                Fields::Unnamed(fields) => {
                    let lengths = fields.unnamed.iter().enumerate().map(|(i, _)| {
                        let index = syn::Index::from(i);
                        quote! { len += self.#index.encoded_length(); }
                    });
                    let encodes = fields.unnamed.iter().enumerate().map(|(i, _)| {
                        let index = syn::Index::from(i);
                        quote! { self.#index.encode(w)?; }
                    });
                    (quote! { #(#lengths)* }, quote! { #(#encodes)* })
                }
                Fields::Unit => (quote! {}, quote! {}),
            };
            (
                quote! { let mut len = 0; #lengths len },
                quote! { #encodes Ok(()) },
            )
        }
        Data::Enum(_) => panic!("enums not supported"),
        Data::Union(_) => panic!("unions not supported"),
    };

    let expanded = quote! {
        impl SiaEncodable for #name {
            fn encoded_length(&self) -> usize {
                #length_impl
            }

            fn encode<W: std::io::Write>(&self, w: &mut W) -> sia_core::encoding::Result<()> {
                #encode_impl
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(SiaDecode)]
pub fn derive_sia_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let decode_impl = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                let decodes = fields.named.iter().filter_map(|f| match f.vis {
                    syn::Visibility::Public(_) => {
                        let name = &f.ident;
                        let ty = &f.ty;
                        Some(quote! { #name: <#ty>::decode(r)?, })
                    }
                    _ => None,
                });
                quote! {
                    Ok(Self {
                        #(#decodes)*
                    })
                }
            }
            Fields::Unnamed(fields) => {
                let decodes = fields.unnamed.iter().map(|f| {
                    let ty = &f.ty;
                    quote! { <#ty>::decode(r)?, }
                });
                quote! {
                    Ok(Self(#(#decodes)*))
                }
            }
            Fields::Unit => quote! { Ok(Self) },
        },
        Data::Enum(_) => panic!("enums not supported"),
        Data::Union(_) => panic!("unions not supported"),
    };

    let expanded = quote! {
        impl SiaDecodable for #name {
            fn decode<R: std::io::Read>(r: &mut R) -> sia_core::encoding::Result<Self> {
                #decode_impl
            }
        }
    };
    TokenStream::from(expanded)
}

#[proc_macro_derive(V1SiaEncode)]
pub fn derive_v1_sia_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let encode_impl = match &input.data {
        Data::Struct(data) => {
            let fields = match &data.fields {
                Fields::Named(fields) => {
                    let encodes = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        quote! { self.#name.encode_v1(enc)?; }
                    });
                    quote! { #(#encodes)* }
                }
                Fields::Unnamed(fields) => {
                    let encodes = fields.unnamed.iter().enumerate().map(|(i, _)| {
                        let index = syn::Index::from(i);
                        quote! { self.#index.encode_v1(enc)?; }
                    });
                    quote! { #(#encodes)* }
                }
                Fields::Unit => quote! {},
            };
            quote! {
                #fields
                Ok(())
            }
        }
        Data::Enum(_) => panic!("enums not supported"),
        Data::Union(_) => panic!("unions not supported"),
    };

    let expanded = quote! {
        impl V1SiaEncodable for #name {
            fn encode_v1<W: std::io::Write>(&self, enc: &mut W) -> sia_core::encoding::Result<()> {
                #encode_impl
            }
        }
    };
    TokenStream::from(expanded)
}

#[proc_macro_derive(V1SiaDecode)]
pub fn derive_v1_sia_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let decode_impl = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                let decodes = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let ty = &f.ty;
                    quote! { #name: <#ty>::decode_v1(r)?, }
                });
                quote! {
                    Ok(Self {
                        #(#decodes)*
                    })
                }
            }
            Fields::Unnamed(fields) => {
                let decodes = fields.unnamed.iter().map(|f| {
                    let ty = &f.ty;
                    quote! { <#ty>::decode_v1(r)?, }
                });
                quote! {
                    Ok(Self(#(#decodes)*))
                }
            }
            Fields::Unit => quote! { Ok(Self) },
        },
        Data::Enum(_) => panic!("enums not supported"),
        Data::Union(_) => panic!("unions not supported"),
    };

    let expanded = quote! {
        impl V1SiaDecodable for #name {
            fn decode_v1<R: std::io::Read>(r: &mut R) -> sia_core::encoding::Result<Self> {
                #decode_impl
            }
        }
    };
    TokenStream::from(expanded)
}

#[proc_macro_derive(AsyncSiaDecode)]
pub fn derive_async_sia_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let decode_impl = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                let decodes = fields.named.iter().filter_map(|f| match f.vis {
                    syn::Visibility::Public(_) => {
                        let name = &f.ident;
                        let ty = &f.ty;
                        Some(quote! { #name: <#ty>::decode_async(r).await?, })
                    }
                    _ => None,
                });
                quote! {
                    Ok(Self {
                        #(#decodes)*
                    })
                }
            }
            Fields::Unnamed(fields) => {
                let decodes = fields.unnamed.iter().map(|f| {
                    let ty = &f.ty;
                    quote! { <#ty>::decode_async(r).await?, }
                });
                quote! {
                    Ok(Self(#(#decodes)*))
                }
            }
            Fields::Unit => quote! { Ok(Self) },
        },
        Data::Enum(_) => panic!("enums not supported"),
        Data::Union(_) => panic!("unions not supported"),
    };

    let expanded = quote! {
        impl sia_core::encoding_async::AsyncSiaDecodable for #name {
            async fn decode_async<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<Self, sia_core::encoding_async::Error> {
                #decode_impl
            }
        }
    };
    TokenStream::from(expanded)
}
