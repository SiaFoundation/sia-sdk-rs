use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

#[proc_macro_derive(SiaEncode)]
pub fn derive_sia_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let encode_impl = match &input.data {
        Data::Struct(data) => {
            let fields = match &data.fields {
                Fields::Named(fields) => {
                    let encodes = fields.named.iter().filter_map(|f| match f.vis {
                        syn::Visibility::Public(_) => {
                            let name = &f.ident;
                            Some(quote! { self.#name.encode(w)?; })
                        }
                        _ => None,
                    });
                    quote! { #(#encodes)* }
                }
                Fields::Unnamed(fields) => {
                    let encodes = fields.unnamed.iter().enumerate().map(|(i, _)| {
                        let index = syn::Index::from(i);
                        quote! { self.#index.encode(w)?; }
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
        impl SiaEncodable for #name {
            fn encode<W: std::io::Write>(&self, w: &mut W) -> crate::encoding::Result<()> {
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
            fn decode<R: std::io::Read>(r: &mut R) -> crate::encoding::Result<Self> {
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
            fn encode_v1<W: std::io::Write>(&self, enc: &mut W) -> crate::encoding::Result<()> {
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
            fn decode_v1<R: std::io::Read>(r: &mut R) -> crate::encoding::Result<Self> {
                #decode_impl
            }
        }
    };
    TokenStream::from(expanded)
}

#[proc_macro_derive(AsyncSiaEncode)]
pub fn derive_async_sia_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let encode_impl = match &input.data {
        Data::Struct(data) => {
            let fields = match &data.fields {
                Fields::Named(fields) => {
                    let encodes = fields.named.iter().filter_map(|f| match f.vis {
                        syn::Visibility::Public(_) => {
                            let name = &f.ident;
                            Some(quote! { self.#name.encode_async(e).await?; })
                        }
                        _ => None,
                    });
                    quote! { #(#encodes)* }
                }
                Fields::Unnamed(fields) => {
                    let encodes = fields.unnamed.iter().enumerate().map(|(i, _)| {
                        let index = syn::Index::from(i);
                        quote! { self.#index.encode_async(e).await?; }
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
        impl AsyncSiaEncodable for #name {
            async fn encode_async<E: crate::encoding_async::AsyncEncoder>(&self, e: &mut E) -> Result<(), E::Error> {
                #encode_impl
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
                        Some(quote! { #name: <#ty>::decode_async(d).await?, })
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
                    quote! { <#ty>::decode_async(d).await?, }
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
        impl AsyncSiaDecodable for #name {
            async fn decode_async<D: crate::encoding_async::AsyncDecoder>(d: &mut D) -> Result<Self, D::Error> {
                #decode_impl
            }
        }
    };
    TokenStream::from(expanded)
}
