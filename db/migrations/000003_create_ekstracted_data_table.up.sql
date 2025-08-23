CREATE TABLE arsip_pro.extracted_data (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID REFERENCES arsip_pro.documents(id) ON DELETE CASCADE,
    doc_type_id UUID REFERENCES arsip_pro.doc_types(id) ON DELETE SET NULL,
    extracted_content JSONB,
    extraction_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);