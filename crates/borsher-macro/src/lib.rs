#![feature(proc_macro_span)]

extern crate proc_macro;

use proc_macro::{Span, TokenStream};
use quote::quote;
use std::fs::{DirBuilder, File};
use std::io::Write;
use std::path::PathBuf;

use syn::{Expr, Item, Lit, PathArguments, Type};

/// Usage: `#[borsher("xxx.ts")]`
#[proc_macro_attribute]
pub fn borsher(attr: TokenStream, body: TokenStream) -> TokenStream {
    let filename = attr.to_string().replace("\"", "");
    let identity = body.clone();
    // inspect the body and generate schema
    // see: https://github.com/nameskyteam/borsher
    let schema_ts = match syn::parse::<Item>(body).unwrap() {
        Item::Mod(module) => borsher_mod(&module),
        Item::Struct(structure) => borsher_struct(&structure),
        Item::Enum(enumerate) => borsher_enum(&enumerate),
        _ => panic!("#[borsher] should be used on mod, enum or struct"),
    };
    // write schema to file
    write_file(filename, schema_ts);
    // should not change anything to the original code
    identity
}

fn write_file(filename: String, schema_ts: String) {
    let call_site = Span::call_site();
    let mut path = PathBuf::new();
    path.push("./");
    path.push(call_site.source_file().path().parent().unwrap().to_path_buf());
    path.push(filename.as_str().trim());
    println!("Writing to file: {}", path.to_str().unwrap());
    // Create the path ignoring existing
    DirBuilder::new()
        .recursive(true)
        .create(path.parent().unwrap())
        .expect("Creates macro output dir");
    let mut target_file = File::create(path.clone()).expect("Creates macro output file");
    target_file.write_all(format!(
        "// Generated file, don't edit!\nimport {{ BorshSchema }} from 'borsher';\n\n{}\n",
        schema_ts
    ).as_bytes()).expect("Writes macro output file");
}

fn map_type(ty: &Type) -> String {
    match ty {
        Type::Tuple(tup) if tup.elems.len() == 0 => "BorshSchema.Unit".to_string(),
        Type::Array(arr) => {
            let len = &arr.len;
            let ty = &arr.elem;
            let len = match len {
                Expr::Lit(l) => match &l.lit {
                    Lit::Int(i ) => i.base10_parse::<usize>().unwrap(),
                    _ => panic!("unsupported array length expr: {}", quote! { #len }.to_string()),
                },
                _ => panic!("unsupported array length expr: {}", quote! { #len }.to_string()),
            };
            format!("BorshSchema.Array({}, {})", map_type(ty), len)
        }
        Type::Path(path) => {
            let segments = &path.path.segments;
            let last_segment = &segments.last().unwrap();
            let ident = &last_segment.ident;
            let args = &last_segment.arguments;
            match ident.to_string().as_str() {
                // simple types
                "u8" => "BorshSchema.u8".to_string(),
                "u16" => "BorshSchema.u16".to_string(),
                "u32" => "BorshSchema.u32".to_string(),
                "u64" => "BorshSchema.u64".to_string(),
                "u128" => "BorshSchema.u128".to_string(),
                "i8" => "BorshSchema.i8".to_string(),
                "i16" => "BorshSchema.i16".to_string(),
                "i32" => "BorshSchema.i32".to_string(),
                "i64" => "BorshSchema.i64".to_string(),
                "i128" => "BorshSchema.i128".to_string(),
                "f32" => "BorshSchema.f32".to_string(),
                "f64" => "BorshSchema.f64".to_string(),
                "bool" => "BorshSchema.bool".to_string(),
                "String" => "BorshSchema.String".to_string(),
                // composite types or custom types
                _ => {
                    let args = match args {
                        // case like: `MessageChannel` in `pub channel: MessageChannel`
                        PathArguments::None => return map_decl_name(ident),
                        // case like: `<u8>` in `Vec<u8>`
                        PathArguments::AngleBracketed(args) => &args.args,
                        _ => panic!(
                            "unsupported path arguments: {}",
                            quote! { #args }.to_string()
                        ),
                    };
                    let args = args
                        .iter()
                        .map(|arg| match arg {
                            syn::GenericArgument::Type(ty) => map_type(ty),
                            _ => panic!(
                                "unsupported generic argument: {}",
                                quote! { #arg }.to_string()
                            ),
                        })
                        .collect::<Vec<_>>();
                    // OK, we only support `Vec` and `Option` for now
                    match ident.to_string().as_str() {
                        "Vec" => format!("BorshSchema.Vec({})", args.join(", ")),
                        "Option" => format!("BorshSchema.Option({})", args.join(", ")),
                        "HashSet" => format!("BorshSchema.HashSet({})", args.join(", ")),
                        "HashMap" => format!("BorshSchema.HashMap({})", args.join(", ")),
                        _ => panic!("unsupported type: {}", quote! { #ty }.to_string()),
                    }
                }
            }
        }
        _ => panic!("unsupported type: {}", quote! { #ty }.to_string()),
    }
}

fn map_decl_name(name: &syn::Ident) -> String {
    name.to_string()
}

fn borsher_struct(structure: &syn::ItemStruct) -> String {
    let name = &structure.ident;
    let fields = &structure.fields;
    let fields_borsh = fields
        .iter()
        .map(|field| {
            let name = &field.ident;
            let ty = &field.ty;
            format!("{}: {}", name.as_ref().unwrap(), map_type(ty))
        })
        .collect::<Vec<_>>();
    // Example schema:
    // const schema = BorshSchema.Struct({
    //   name: BorshSchema.String,
    //   age: BorshSchema.u8
    // });
    format!(
        "export const {} = BorshSchema.Struct({{\n{}\n}});",
        map_decl_name(name),
        fields_borsh.join(",\n")
    )
}

fn borsher_enum(enumerate: &syn::ItemEnum) -> String {
    let name = &enumerate.ident;
    let variants = &enumerate.variants;
    let variants_borsh = variants
        .iter()
        .map(|variant| {
            let name = &variant.ident;
            let fields = &variant.fields;
            match fields {
                syn::Fields::Unit => format!("{}: BorshSchema.Unit", name),
                syn::Fields::Named(fields) => {
                    let fields_borsh = fields
                        .named
                        .iter()
                        .map(|field| {
                            let name = &field.ident;
                            let ty = &field.ty;
                            format!("{}: {}", name.as_ref().unwrap(), map_type(ty))
                        })
                        .collect::<Vec<_>>();
                    format!(
                        "{}: BorshSchema.Struct({{\n{}\n}})",
                        name,
                        fields_borsh.join(",\n")
                    )
                }
                syn::Fields::Unnamed(fields) => {
                    let fields_borsh = fields
                        .unnamed
                        .iter()
                        .map(|field| {
                            let ty = &field.ty;
                            map_type(ty)
                        })
                        .collect::<Vec<_>>();
                    match fields_borsh.len() {
                        0 => format!("{}: BorshSchema.Empty", name),
                        1 => format!("{}: {}", name, fields_borsh.first().unwrap()),
                        // _ => format!("{}: BorshSchema.Tuple({})", name, fields_borsh.join(", ")),
                        _ => panic!("BorshScema does not have a Tuple variant, please use named fileds instead of unnamed ones: {}",
                        quote! { #variant }.to_string()
                        ),
                    }
                }
            }
        })
        .collect::<Vec<_>>();
    // Example schema:
    // const schema = BorshSchema.Enum({
    //   Normal: BorshSchema.Unit,
    //   OffchainControl: BorshSchema.u8,
    //   TunnelNegotiate: BorshSchema.Unit
    // });
    format!(
        "export const {} = BorshSchema.Enum({{\n{}\n}});",
        map_decl_name(name),
        variants_borsh.join(",\n")
    )
}

fn borsher_mod(module: &syn::ItemMod) -> String {
    module
        .content
        .as_ref()
        .unwrap()
        .1
        .iter()
        .filter_map(|item| match item {
            Item::Struct(structure) => Some(borsher_struct(structure)),
            Item::Enum(enumerate) => Some(borsher_enum(enumerate)),
            Item::Mod(module) => Some(borsher_mod(module)),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}
