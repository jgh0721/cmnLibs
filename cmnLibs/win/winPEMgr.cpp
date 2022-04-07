#include "winPEMgr.hpp"

#include <queue>
#include <cassert>

using namespace nsCmn::nsPE::nsDetail;

namespace nsCmn
{
    namespace nsPE
    {
        namespace nsDetail
        {
            TyRsrcData::TyRsrcData( uint8_t* Buffer, uint32_t BufferSize, DWORD CodePage, DWORD Offset )
            {
                SetData( Buffer, BufferSize );
                this->CodePage = CodePage;
                this->Offset = Offset;
            }

            void TyRsrcData::SetData( uint8_t* Buffer, uint32_t BufferSize )
            {
                this->Buffer.resize( BufferSize );
                memset( &(this->Buffer[0]), '\0', this->Buffer.size() );
                memcpy( this->Buffer.data(), Buffer, BufferSize );
            }

            TyRsrcDirectoryEntry::TyRsrcDirectoryEntry( const WCHAR* Name, TyRsrcDirectory* Child )
            {
                if( IS_INTRESOURCE( Name ) || ( Name[0] == L'#' )  )
                {
                    IsName = false;

                    if( IS_INTRESOURCE( Name ) )
                        Id = ( WORD )( ULONG_PTR )Name;
                    else
                        Id = (WORD)_wtoi( Name + 1 );
                }
                else
                {
                    IsName = true;
                    this->Name = Name;
                }

                IsDirectory = true;
                Directory = Child;
            }

            TyRsrcDirectoryEntry::TyRsrcDirectoryEntry( const WCHAR* Name, TyRsrcData* Data )
            {
                if( IS_INTRESOURCE( Name ) || ( Name[0] == L'#' )  )
                {
                    IsName = false;

                    if( IS_INTRESOURCE( Name ) )
                        Id = ( WORD )( ULONG_PTR )Name;
                    else
                        Id = (WORD)_wtoi( Name + 1 );
                }
                else
                {
                    IsName = true;
                    this->Name = Name;
                }

                IsDirectory = false;
                Leaf = Data;
            }

            TyRsrcDirectory* TyRsrcDirectoryEntry::GetChild()
            {
                return Directory;
            }

            TyRsrcData* TyRsrcDirectoryEntry::GetData()
            {
                return Leaf;
            }

            TyRsrcDirectory::TyRsrcDirectory( IMAGE_RESOURCE_DIRECTORY* Res )
            {
                memset( &this->Rsrc, '\0', sizeof( IMAGE_RESOURCE_DIRECTORY ) );

                this->Rsrc = *Res;
                this->Rsrc.NumberOfIdEntries = 0;
                this->Rsrc.NumberOfNamedEntries = 0;
            }

            IMAGE_RESOURCE_DIRECTORY TyRsrcDirectory::GetInfo() const
            {
                return Rsrc;
            }

            DWORD TyRsrcDirectory::GetSize()
            {
                DWORD dwSize = sizeof( IMAGE_RESOURCE_DIRECTORY );

                for( unsigned int i = 0; i < Entries.size(); i++ )
                {
                    dwSize += sizeof( IMAGE_RESOURCE_DIRECTORY_ENTRY );
                    if( Entries[ i ]->IsName )
                        dwSize += sizeof( IMAGE_RESOURCE_DIR_STRING_U ) + ( Entries[ i ]->Name.length() ) * sizeof( WCHAR );
                    if( Entries[ i ]->IsDirectory )
                        dwSize += Entries[ i ]->GetChild()->GetSize();
                    else
                    {
                        DWORD dwAligned = Entries[ i ]->GetData()->GetSize();
                        dwAligned = ROUND_UP( dwAligned, 8 );
                        dwSize += sizeof( IMAGE_RESOURCE_DATA_ENTRY ) + dwAligned;
                    }
                }

                return dwSize;
            }

            void TyRsrcDirectory::Destroy()
            {
                for( unsigned int i = 0; i < Entries.size(); i++ )
                {
                    if( Entries[ i ]->IsDirectory )
                    {
                        Entries[ i ]->GetChild()->Destroy();
                        delete Entries[ i ]->GetChild();
                    }
                    else
                        delete Entries[ i ]->GetData();
                }
            }

            TyRsrcDirectoryEntry* TyRsrcDirectory::GetEntry( uint32_t Index )
            {
                if( Entries.size() < Index )
                    return nullptr;

                return Entries[ Index ];
            }

            void TyRsrcDirectory::AddEntry( TyRsrcDirectoryEntry* Entry )
            {
                // 리소스 디렉토리 내에서 리소스들은 정렬된 상태를 유지해야한다.
                // 문자열 리소스 -> Id 리소스
                // 문자열은 wcscmp 비교 순
                // Id 리소느는 오름차순

                // Entries 배열에서 삽입될 위치
                int i = 0;

                if( Entry->IsName )
                {
                    auto szEntName = Entry->Name;
                    for( i = 0; i < Rsrc.NumberOfNamedEntries; i++ )
                    {
                        int cmp = wcscmp( Entries[ i ]->Name.c_str(), szEntName.c_str() );

                        // 같은 이름이 이미 존재함
                        if( cmp == 0 )
                            return;

                        if( cmp > 0 )
                            break;
                    }

                    Rsrc.NumberOfNamedEntries++;
                }
                else
                {
                    for( i = Rsrc.NumberOfNamedEntries; i < Rsrc.NumberOfNamedEntries + Rsrc.NumberOfIdEntries; i++ )
                    {
                        if( Entries[ i ]->GetId() == Entry->GetId() )
                            return;
                        if( Entries[ i ]->GetId() > Entry->GetId() )
                            break;
                    }
                    Rsrc.NumberOfIdEntries++;
                }

                Entries.insert( Entries.begin() + i, Entry );
            }

            void TyRsrcDirectory::RemoveEntry( uint32_t Idx )
            {
                if( Entries[ Idx ]->IsName )
                    Rsrc.NumberOfNamedEntries--;
                else
                    Rsrc.NumberOfIdEntries--;

                delete Entries[ Idx ];

                Entries.erase( Entries.begin() + Idx );
            }

            int TyRsrcDirectory::CountEntries() const
            {
                return Entries.size();
            }

            uint32_t TyRsrcDirectory::FindIndex( wchar_t* Name )
            {
                if( IS_INTRESOURCE( Name ) )
                    return FindIndex( ( WORD )( ULONG_PTR )Name );
                else
                {
                    if( Name[ 0 ] == L'#' )
                        return FindIndex( WORD( _wtoi( Name + 1 ) ) );
                }

                for( unsigned int i = 0; i < Entries.size(); i++ )
                {
                    if( !Entries[ i ]->IsName )
                        continue;

                    if( wcscmp( Name, Entries[ i ]->Name.c_str() ) == 0 )
                        return i;
                }

                return UINT_MAX;
            }

            uint32_t TyRsrcDirectory::FindIndex( WORD Id )
            {
                for( unsigned int i = 0; i < Entries.size(); i++ )
                {
                    if( Entries[ i ]->IsName )
                        continue;

                    if( Id == Entries[ i ]->Id )
                        return i;
                }

                return UINT_MAX;
            }

        } // nsDetail

        ///////////////////////////////////////////////////////////////////////

        DWORD CvtRVAToOFFSET( IMAGE_SECTION_HEADER *pISH, DWORD RVA )
        {
            return ( RVA - pISH->VirtualAddress + pISH->PointerToRawData );
        }

        DWORD CvtOFFSETToRVA( IMAGE_SECTION_HEADER *pISH, DWORD OFFSET )
        {
            return ( OFFSET - pISH->PointerToRawData + pISH->VirtualAddress );
        }

        ///////////////////////////////////////////////////////////////////////

        CPEMgr::~CPEMgr()
        {
            cleanup();
        }

        DWORD CPEMgr::SetFile( const std::wstring& FilePath, bool IsReadOnly )
        {
            DWORD Err = ERROR_SUCCESS;
            HANDLE hMapping = NULL;

            do
            {
                _hFile = CreateFileW( FilePath.c_str(),
                                      GENERIC_READ,
                                      FILE_SHARE_READ,
                                      NULL,
                                      OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, NULL );

                if( _hFile == INVALID_HANDLE_VALUE )
                {
                    Err = GetLastError();
                    break;
                }

                hMapping = CreateFileMappingW( _hFile, NULL, PAGE_READONLY, 0, 0, NULL );
                if( hMapping == NULL )
                {
                    Err = GetLastError();
                    break;
                }

                _base = (uint8_t*)MapViewOfFile( hMapping, FILE_MAP_READ, 0, 0, 0 );
                if( _base == nullptr )
                {
                    Err = GetLastError();
                    break;
                }


                _baseSize = GetFileSize( _hFile, NULL );
                _isReadOnly = IsReadOnly;

                if( _isReadOnly == false )
                {
                    uint8_t* buffer = ( uint8_t* ) malloc( _baseSize );
                    if( buffer == nullptr )
                    {
                        Err = ERROR_OUTOFMEMORY;
                        break;
                    }

                    memcpy( buffer, _base, _baseSize );
                    UnmapViewOfFile( _base );
                    _base = buffer;
                }

                Err = scan();

                assert( _resRoot->GetSize() == CalcSizeOfRsrc() );

            } while( false );

            if( hMapping != NULL )
                CloseHandle( hMapping );

            if( Err != ERROR_SUCCESS )
            {
                if( _hFile != INVALID_HANDLE_VALUE )
                    CloseHandle( _hFile );
                _hFile = INVALID_HANDLE_VALUE;
            }

            return Err;
        }

        CPEMgr::TyEnFileType CPEMgr::GetFileType() const
        {
            return _eFileType;
        }

        std::pair<IMAGE_NT_HEADERS*, std::wstring> CPEMgr::GetNTHeaders( PBYTE Base /* = nullptr */ )
        {
            std::pair<IMAGE_NT_HEADERS*, std::wstring> Result( nullptr, L"" );

            do
            {
                if( Base == nullptr )
                    Base = GetBase();

                // Get dos header
                PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER )Base;
                if( dosHeader->e_magic != IMAGE_DOS_SIGNATURE )
                {
                    Result.second = L"PE file contains invalid DOS header";
                    break;
                }

                // Get NT headers
                PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS )( Base + ( DWORD )dosHeader->e_lfanew );
                if( ntHeaders->Signature != IMAGE_NT_SIGNATURE )
                {
                    Result.second = L"PE file missing NT signature";
                    break;
                }

                // Make sure this is a supported PE format
                if( ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                    ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
                {
                    Result.second = L"Unsupported PE format";
                    break;
                }

                Result.first = ntHeaders;

            } while( false );

            return Result;
        }

        std::vector<uint8_t> CPEMgr::RebuildPE()
        {
            std::vector<uint8_t> Stub;
            auto SrcNtHDR = GetNTHeaders().first;

            uint32_t SrcSectionAlignment = GetMemberFromOptionalHeader( SrcNtHDR->OptionalHeader, SectionAlignment );
            uint32_t SrcFileAlignment = GetMemberFromOptionalHeader( SrcNtHDR->OptionalHeader, FileAlignment );
            uint32_t SrcSizeOfImage = GetMemberFromOptionalHeader( SrcNtHDR->OptionalHeader, SizeOfImage );
            uint32_t RawRsrcSize = CalcSizeOfRsrc();

            if( SrcSectionAlignment <= 0 || SrcFileAlignment <= 0 )
                return Stub;

            Stub.resize( _baseSize );
            memcpy( &Stub[0], _base, _baseSize );

            IMAGE_SECTION_HEADER* SrcSecRsrc = retrieveRsrcSection( _base );
            IMAGE_SECTION_HEADER* DstSecRsrc = retrieveRsrcSection( &Stub[ 0 ] );

            auto DstNtHDR = GetNTHeaders( &Stub[ 0 ] ).first;

            if( DstSecRsrc == nullptr )
            {
                // 리소스 섹션이 존재하지 않음, 추가한다
                DWORD NumSection = 0;
                DstSecRsrc = firstSecHDR( &Stub[ 0 ], &NumSection );
                DstSecRsrc += NumSection;
                DstNtHDR->FileHeader.NumberOfSections++;

                memset( DstSecRsrc, 0, sizeof( IMAGE_SECTION_HEADER ) );
                memcpy( DstSecRsrc->Name, ".rsrc", 5 );
                DstSecRsrc->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
                DstSecRsrc->VirtualAddress = SrcSizeOfImage;
                // 파일의 마지막이 PE 섹션이 시작이 될 것이므로 현재 이미지의 크기가 리소스 섹션의 시작이 된다
                // 만약 해당 파일에 인증서가 있다면 덮어씌워진다

                // IMAGE_DATA_DIRECTORY 의 내용은 이후 코드에서 기록한다
            }

            // 섹션만 존재하고 데이터가 없거나, 막 섹션을 추가한 경우
            if( DstSecRsrc->PointerToRawData == 0 )
            {
                // 파일에 기록될 때에는 FileAlignment 로 정렬되어야한다
                DstSecRsrc->PointerToRawData = ROUND_UP( (uint32_t)_baseSize, SrcFileAlignment );
                DstSecRsrc->SizeOfRawData = 0;
            }

            DWORD SrcSecRsrcSize = SrcSecRsrc->SizeOfRawData;
            DWORD DstSecRsrcSize = ROUND_UP( RawRsrcSize, SrcFileAlignment );   // 변경된 리소스 크기

            // 섹션의 크기가 변경되었다면 크기 변경 등의 작업을 처리한다
            // DstSecRsrc->SizeOfRawData, 기존에 PE 에서 가지고 있던 리소스 크기
            if( DstSecRsrcSize != DstSecRsrc->SizeOfRawData )
            {
                DWORD virtual_section_size = ROUND_UP( RawRsrcSize, SrcSectionAlignment );
                int delta = DstSecRsrcSize - ( DstSecRsrc->SizeOfRawData + ( -DstSecRsrc->SizeOfRawData ) % SrcFileAlignment );
                // 양 섹션간의 RVA 변화량 계산
                int rva_delta = virtual_section_size - ( DstSecRsrc->Misc.VirtualSize + ( -DstSecRsrc->Misc.VirtualSize ) % SrcSectionAlignment );
                // 기존에 리소스 섹션이 파일의 마지막 섹션인지 확인
                bool isLastSection = DstSecRsrc->PointerToRawData + DstSecRsrc->SizeOfRawData >= _baseSize;
                // 실제 변경될 최종 이미지 크기 계산
                DWORD DstImageSize = isLastSection ? DstSecRsrc->PointerToRawData + DstSecRsrcSize : _baseSize + delta;

                /*!
                 * 파일 크기 변경, 경우의 수
                 * 리소스 섹션이 마지막의 경우,
                 *  항상 파일의 크기를 늘린 후, 리소스 섹션을 기록한다. 별도 정리 필요없음
                 * 리소스 섹션이 처음 또는 중간의 경우
                 *  크기가 줄어듬
                 *      리소스 섹션을 제외하고, 리소스 섹션 뒤에 있는 섹션의 데이터를 앞으로 이동 시킨 후 크기를 줄인다
                 *  크기가 늘어남
                 *      파일의 크기를 늘린 후, 리소스 섹션 뒤에 있는 섹션의 데이터를 뒤로 이동 시킨다
                */
                // resize_after => true, 파일의 크기가 줄어듬, => false, 파일의 크기가 늘어남
                bool resize_after = DstImageSize < _baseSize && !isLastSection;

                // 파일의 크기가 늘어남
                if( !resize_after )
                {
                    Stub.resize( DstImageSize );
                    DstNtHDR = GetNTHeaders( &Stub[ 0 ] ).first;
                    DstSecRsrc =  retrieveRsrcSection( &Stub[ 0 ] );
                }

                if( !isLastSection )
                {
                    // 리소스 섹션이 처음 또는 중간에 있으므로 리소스 섹션 뒤의 섹션 들을 조정한다
                    DWORD SrcSecRsrcEndPtr = DstSecRsrc->PointerToRawData + DstSecRsrc->SizeOfRawData;

                    memmove( AddToPtr( Stub.data(), SrcSecRsrcEndPtr + delta ),
                             AddToPtr( Stub.data(), SrcSecRsrcEndPtr ),
                             _baseSize - SrcSecRsrcEndPtr );
                    DWORD SecCount = 0;
                    auto DstSecHDR = firstSecHDR( &Stub[ 0 ], &SecCount );
                    for( int i = 0; i < SecCount; ++i )
                    {
                        if( DstSecHDR[ i ].PointerToRawData > DstSecRsrc->PointerToRawData )
                        {
                            DstSecHDR[ i ].PointerToRawData += delta;
                            DstSecHDR[ i ].VirtualAddress += rva_delta;
                        }
                    }
                }

                // 파일의 크기가 줄어듬
                if( resize_after )
                {
                    Stub.resize( DstImageSize );
                    DstNtHDR = GetNTHeaders( &Stub[ 0 ] ).first;
                    DstSecRsrc = retrieveRsrcSection( &Stub[ 0 ] );
                }

                // 추가적인 PE 헤더 정보 조정
                DstSecRsrc->SizeOfRawData = DstSecRsrcSize;
                DstSecRsrc->Misc.VirtualSize = RawRsrcSize;

                if( DstNtHDR->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC )
                {
                    auto DstNtHDR64 = ( IMAGE_NT_HEADERS64* )DstNtHDR;

                    DstNtHDR64->OptionalHeader.SizeOfImage += rva_delta;
                    DstNtHDR64->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_RESOURCE ].VirtualAddress = DstSecRsrc->VirtualAddress;
                    DstNtHDR64->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_RESOURCE ].Size = RawRsrcSize;
                    DstNtHDR64->OptionalHeader.SizeOfInitializedData = calcInitializedDataSize( &Stub[0] );

                    for( int i = 0; i < DstNtHDR64->OptionalHeader.NumberOfRvaAndSizes; i++ )
                    {
                        if( DstNtHDR64->OptionalHeader.DataDirectory[ i ].VirtualAddress > DstSecRsrc->VirtualAddress )
                            DstNtHDR64->OptionalHeader.DataDirectory[ i ].VirtualAddress += rva_delta;
                    }

                    DstNtHDR64->OptionalHeader.SizeOfHeaders = calcSizeOfHeaders( Stub.data() );
                }
                else
                {
                    auto DstNtHDR32 = ( IMAGE_NT_HEADERS32* )DstNtHDR;

                    DstNtHDR32->OptionalHeader.SizeOfImage += rva_delta;
                    DstNtHDR32->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_RESOURCE ].VirtualAddress = DstSecRsrc->VirtualAddress;
                    DstNtHDR32->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_RESOURCE ].Size = RawRsrcSize;
                    DstNtHDR32->OptionalHeader.SizeOfInitializedData = calcInitializedDataSize( &Stub[ 0 ] );

                    for( int i = 0; i < DstNtHDR32->OptionalHeader.NumberOfRvaAndSizes; i++ )
                    {
                        if( DstNtHDR32->OptionalHeader.DataDirectory[ i ].VirtualAddress > DstSecRsrc->VirtualAddress )
                            DstNtHDR32->OptionalHeader.DataDirectory[ i ].VirtualAddress += rva_delta;
                    }

                    DstNtHDR32->OptionalHeader.SizeOfHeaders = calcSizeOfHeaders( Stub.data() );
                }

                patchRVAs( _base, _baseSize, Stub, SrcNtHDR, DstNtHDR, delta, rva_delta );
                DstSecRsrc->SizeOfRawData = DstSecRsrcSize;
            }

            auto DstSecRsrcBase = AddToPtr<PBYTE>( Stub.data(), DstSecRsrc->PointerToRawData );
            writeRsrcSecTo( DstSecRsrcBase );
            writeRsrcSecPaddingTo( DstSecRsrcBase + RawRsrcSize, DstSecRsrcSize - RawRsrcSize );

            return Stub;
        }

        DWORD CPEMgr::CalcChecksum()
        {
            return calcChecksum( _base, _baseSize );
        }

        DWORD CPEMgr::CalcSizeOfRsrc()
        {
            return calcSizeOfRsrc( _resRoot );
        }

        std::vector<uint8_t> CPEMgr::GetResource( WCHAR* Type, WCHAR* NameOrId, LANGID LangID )
        {
            return getResource( Type, NameOrId, LangID );
        }

        bool CPEMgr::UpdResource( WCHAR* Type, WCHAR* NameOrId, std::vector< uint8_t >& Buffer, LANGID LangID )
        {
            return UpdResource( Type, NameOrId, Buffer.data(), Buffer.size(), LangID );
        }

        bool CPEMgr::UpdResource( WCHAR* Type, WCHAR* NameOrId, uint8_t* Buffer, uint32_t BufferSize, LANGID LangID )
        {
            return updResource( Type, NameOrId, LangID, Buffer, BufferSize );
        }

        bool CPEMgr::EnumerateCertificates( WORD TypeFilter, PDWORD CertificateCount, PDWORD Indices, DWORD IndexCount )
        {
            DWORD size, count, offset, sd_VirtualAddr, index;
            WIN_CERTIFICATE hdr;
            const size_t cert_hdr_size = sizeof hdr - sizeof hdr.bCertificate;
            if( retrieveSecurityDirOffset( _base, &sd_VirtualAddr, &size ) == false )
                return false;

            offset = 0;
            index = 0;
            *CertificateCount = 0;
            while( offset < size )
            {
                /* read the length of the current certificate */
                if( sd_VirtualAddr + offset >= _baseSize )
                    return false;

                hdr = *AddToPtr< WIN_CERTIFICATE *>( _base, ( sd_VirtualAddr + offset ) );

                /* check the certificate is not too big or too small */
                if( hdr.dwLength < cert_hdr_size )
                    return FALSE;
                if( hdr.dwLength > ( size - offset ) )
                    return FALSE;

                if( ( TypeFilter == CERT_SECTION_TYPE_ANY ) ||
                    ( TypeFilter == hdr.wCertificateType ) )
                {
                    ( *CertificateCount )++;
                    if( Indices && *CertificateCount <= IndexCount )
                        *Indices++ = index;
                }

                /* next certificate */
                offset += hdr.dwLength;

                /* padded out to the nearest 8-byte boundary */
                if( hdr.dwLength % 8 )
                    offset += 8 - ( hdr.dwLength % 8 );

                index++;
            }

            return true;
        }

        bool CPEMgr::GetCertificateHeader( DWORD CertificateIndex, LPWIN_CERTIFICATE CertificateHeader )
        {
            if( IsNTSignature( GetBase() ) == false )
                return false;

            DWORD_PTR CurrentCert;
            bool rc;

            rc = false;

            do
            {
                auto NtHDRPtr = GET_NT_HDR_PTR( GetBase() );
                if( NtHDRPtr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                    NtHDRPtr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
                    break;

                auto DataDir = GetMemberFromOptionalHeader( NtHDRPtr->OptionalHeader, DataDirectory )[ IMAGE_DIRECTORY_ENTRY_SECURITY ];
                auto SizeOfImage = GetMemberFromOptionalHeader( NtHDRPtr->OptionalHeader, SizeOfImage );

                // Check if the cert pointer is at least reasonable.
                if( !DataDir.VirtualAddress ||
                    !DataDir.Size ||
                    ( DataDir.VirtualAddress + DataDir.Size > SizeOfImage ) )
                {
                    break;
                }

                // We're not looking at an empty security slot or an invalid (past the image boundary) value.
                // Let's see if we can find it.

                DWORD CurrentIdx = 0;
                DWORD_PTR LastCert;

                CurrentCert = ( DWORD_PTR )( GetBase() + DataDir.VirtualAddress );
                LastCert = CurrentCert + DataDir.Size;

                while( CurrentCert < LastCert )
                {
                    if( CurrentIdx == CertificateIndex )
                    {
                        rc = true;
                        break;
                    }

                    CurrentIdx++;
                    CurrentCert += ( ( LPWIN_CERTIFICATE )CurrentCert )->dwLength;
                    CurrentCert = ( CurrentCert + 7 ) & ~7;   // align it.
                }
            } while( false );

            if( rc == true )
            {
                memcpy( CertificateHeader, (LPWIN_CERTIFICATE)CurrentCert, sizeof( WIN_CERTIFICATE ) );
            }

            return( rc );
        }

        bool CPEMgr::RemoveCertificates()
        {
            auto Count = GetCertificateCount();
            if( Count == 0 )
                return true;

            if( _isReadOnly == true )
                return false;

            bool isSuccess = false;

            for( DWORD idx = 0; idx < Count; ++idx )
            {
                isSuccess = removeCertificate( _base, _baseSize, idx );
                if( isSuccess == false )
                    break;
            }

            if( isSuccess )
            {
                // 체크섬 재기록
                GetMemberFromOptionalHeader( GetNTHeaders( _base ).first->OptionalHeader, CheckSum ) = CalcChecksum();
            }

            return isSuccess;
        }

        DWORD CPEMgr::GetCertificateCount()
        {
            DWORD CertificateCount = 0;
            EnumerateCertificates( CERT_SECTION_TYPE_ANY, &CertificateCount, nullptr, 0  );
            return CertificateCount;
        }

        void CPEMgr::cleanup()
        {
            if( _isReadOnly == true)
            {
                UnmapViewOfFile( _base );

                if( _hFile != INVALID_HANDLE_VALUE )
                    CloseHandle( _hFile );
            }
            else
            {
                if( _base != nullptr )
                {
                    free( _base );
                    _base = nullptr;
                }
            }
        }

        DWORD CPEMgr::scan()
        {
            DWORD Err = ERROR_SUCCESS;

            do
            {
                _eFileType = PE_FILE_TYPE_UNKNOWN;

                if( IsDosSignature( _base ) == false )
                    break;

                _eFileType = PE_FILE_TYPE_DOS;

                if( IsNTSignature( _base ) == false )
                    break;

                if( Is32bitPE( _base ) == true )
                    _eFileType = PE_FILE_TYPE_NT_X86;
                else
                    _eFileType = PE_FILE_TYPE_NT_X64;

                auto firstSectionHDR = firstSecHDR( _base );
                auto NtHDR = GET_NT_HDR_PTR( _base );
                auto rsrcDataDir = GetMemberFromOptionalHeader(NtHDR->OptionalHeader, DataDirectory)[IMAGE_DIRECTORY_ENTRY_RESOURCE];

                auto rsrcSecHDR = findSecHDRByRVA( _base, rsrcDataDir.VirtualAddress );

                auto Root = AddToPtr<IMAGE_RESOURCE_DIRECTORY*>( _base, rsrcSecHDR->PointerToRawData );

                _resRoot = scanRsrcSection( Root, Root );

            } while( false );

            return Err;
        }

        nsDetail::TyRsrcDirectory* CPEMgr::scanRsrcSection( IMAGE_RESOURCE_DIRECTORY* Root, IMAGE_RESOURCE_DIRECTORY* Scan )
        {
            nsDetail::TyRsrcDirectory* Ret = nullptr;
            WCHAR* Name = nullptr;

            if( Root == nullptr || Scan == nullptr )
                return Ret;

            Ret = new nsDetail::TyRsrcDirectory( ( IMAGE_RESOURCE_DIRECTORY* )Scan );

            std::wstring sName;
            PIMAGE_RESOURCE_DATA_ENTRY rde = NULL;

            // Go through all entries of this resource directory
            int entries = Scan->NumberOfNamedEntries;
            entries += Scan->NumberOfIdEntries;

            for( int i = 0; i < entries; i++ )
            {
                IMAGE_RESOURCE_DIRECTORY_ENTRY rd = *AddToPtr< IMAGE_RESOURCE_DIRECTORY_ENTRY * >( Scan, sizeof( IMAGE_RESOURCE_DIRECTORY ) +  i * sizeof( IMAGE_RESOURCE_DIRECTORY_ENTRY ) );

                // If this entry points to data entry get a pointer to it
                if( !rd.DataIsDirectory )
                    rde = PIMAGE_RESOURCE_DATA_ENTRY( rd.OffsetToData + ( BYTE* )Root );

                // If this entry has a name, translate it from Unicode
                if( rd.NameIsString )
                {
                    PIMAGE_RESOURCE_DIR_STRING_U rds = PIMAGE_RESOURCE_DIR_STRING_U( rd.NameOffset + ( char* )Root );

                    sName = std::wstring( rds->NameString, rds->Length );
                }
                    // Else, set the name to this entry's id
                else
                {
                    WCHAR Buffer[ 32 ] = { 0, };
                    swprintf( Buffer, L"#%d", rd.Id );
                    sName = Buffer;
                }

                if( rd.DataIsDirectory )
                {
                    Ret->AddEntry(
                            new nsDetail::TyRsrcDirectoryEntry(
                                    sName.c_str(),
                                    scanRsrcSection(
                                            Root,
                                            AddToPtr<IMAGE_RESOURCE_DIRECTORY*>( Root, rd.OffsetToDirectory )
                                                   )
                                              )
                                 );
                }
                else
                {
                    DWORD dwOffset = CvtRVAToOFFSET( retrieveRsrcSection( _base ), rde->OffsetToData );
                    LPBYTE pbData = AddToPtr<LPBYTE>( _base, dwOffset );

                    if( dwOffset > DWORD( _baseSize ) )
                    {
                        // Invalid resource entry data pointer, possibly compressed resources;

                        delete Ret;
                        Ret = nullptr;
                        break;
                    }

                    Ret->AddEntry( new nsDetail::TyRsrcDirectoryEntry( sName.c_str(),
                                                                       new nsDetail::TyRsrcData( pbData,
                                                                                                 rde->Size,
                                                                                                 rde->CodePage,
                                                                                                 dwOffset
                                                                                               )
                                                                     )
                                 );
                }

                // Delete the dynamicly allocated name if it is a name and not an id
                if( !IS_INTRESOURCE( Name ) )
                    delete[] Name;

                Name = nullptr;
            } // for

            return Ret;
        }

        IMAGE_SECTION_HEADER *CPEMgr::firstSecHDR( uint8_t *Base, DWORD* SectionCount /* = nullptr */ ) const
        {
            auto pnh = ( IMAGE_NT_HEADERS32 * ) GET_NT_HDR_PTR( Base );

            if( SectionCount != nullptr )
                *SectionCount = pnh->FileHeader.NumberOfSections;

            return ( ( IMAGE_SECTION_HEADER * )
                    ( ( ULONG_PTR ) ( pnh ) + FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +
                      ( pnh->FileHeader.SizeOfOptionalHeader ) ) );
        }

        IMAGE_SECTION_HEADER* CPEMgr::findSecHDRByRVA( uint8_t* ImgBase, DWORD RVA, DWORD* SecIndex ) const
        {
            auto NTHDR = GET_NT_HDR_PTR( ImgBase );
            auto FIRST_SECTION_HDR = firstSecHDR( ImgBase );

            if( SecIndex != nullptr )
                *SecIndex = UINT_MAX;

            for( WORD idx = 0; idx < NTHDR->FileHeader.NumberOfSections; ++idx )
            {
                if( RVA >= FIRST_SECTION_HDR[idx].VirtualAddress &&
                    RVA < FIRST_SECTION_HDR[idx].VirtualAddress + FIRST_SECTION_HDR[idx].Misc.VirtualSize )
                {
                    if( SecIndex != nullptr )
                        *SecIndex = idx;

                    return &FIRST_SECTION_HDR[ idx ];
                }
            }

            return nullptr;
        }

        IMAGE_SECTION_HEADER *CPEMgr::findSecHDRByOffset( uint8_t* ImgBase, DWORD Offset )
        {
            auto NTHDR = GET_NT_HDR_PTR( ImgBase );
            auto FIRST_SECTION_HDR = firstSecHDR( ImgBase );

            for( WORD idx = 0; idx < NTHDR->FileHeader.NumberOfSections; ++idx )
            {
                if( Offset >= FIRST_SECTION_HDR[idx].PointerToRawData &&
                    Offset < FIRST_SECTION_HDR[idx].PointerToRawData + FIRST_SECTION_HDR[idx].SizeOfRawData )
                {
                    return &FIRST_SECTION_HDR[ idx ];
                }
            }

            return nullptr;
        }

        IMAGE_DATA_DIRECTORY* CPEMgr::retrieveDataDirs( uint8_t* ImageBase )
        {
            auto NtHDR = GetNTHeaders( ImageBase ).first;
            return GetMemberFromOptionalHeader( NtHDR->OptionalHeader, DataDirectory );
        }

        IMAGE_DATA_DIRECTORY* CPEMgr::retrieveDataDirById( uint8_t* ImageBase, ULONG Id )
        {
            auto pdds = retrieveDataDirs( ImageBase );
            return &pdds[ Id ];
        }

        /*++

        Routine Description:

            Compute a partial checksum on a portion of an imagefile.

        Arguments:

            PartialSum - Supplies the initial checksum value.

            Sources - Supplies a pointer to the array of words for which the
                checksum is computed.

            Length - Supplies the length of the array in words.

        Return Value:

            The computed checksum value is returned as the function value.

        --*/
        USHORT ChkSum( ULONG PartialSum, PUSHORT Source, ULONG Length )
        {
            //
            // Compute the word wise checksum allowing carries to occur into the
            // high order half of the checksum longword.
            //

            while (Length--) {
                PartialSum += *Source++;
                PartialSum = (PartialSum >> 16) + (PartialSum & 0xffff);
            }

            //
            // Fold final carry into a single word result and return the resultant
            // value.
            //

            return (USHORT)(((PartialSum >> 16) + PartialSum) & 0xffff);
        }

        DWORD CPEMgr::calcChecksum( uint8_t* ImgBase, uint32_t ImgSize )
        {
            PUSHORT AdjustSum;
            PIMAGE_NT_HEADERS NtHeaders;
            USHORT PartialSum;
            PBYTE pbyte;

            // Compute the checksum of the file and zero the header checksum value.

            PartialSum = ChkSum(0, (PUSHORT)ImgBase, ImgSize >> 1 );

            // If the file is an image file, then subtract the two checksum words
            // in the optional header from the computed checksum before adding
            // the file length, and set the value of the header checksum.

            NtHeaders = GetNTHeaders( ImgBase ).first;

            if(( NtHeaders != NULL ) && ( (LPVOID)NtHeaders != (LPVOID)ImgBase ))
            {
                if( NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC )
                    AdjustSum = ( PUSHORT ) ( &(( PIMAGE_NT_HEADERS32 ) NtHeaders )->OptionalHeader.CheckSum );
                else if( NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC )
                    AdjustSum = ( PUSHORT ) ( &(( PIMAGE_NT_HEADERS64 ) NtHeaders )->OptionalHeader.CheckSum );
                else
                    return 0;

                PartialSum -= ( PartialSum < AdjustSum[ 0 ] );
                PartialSum -= AdjustSum[ 0 ];
                PartialSum -= ( PartialSum < AdjustSum[ 1 ] );
                PartialSum -= AdjustSum[ 1 ];
            }

            // add the last byte, if needed

            if( ImgSize % 2 )
            {
                pbyte      = ( PBYTE )ImgBase + ImgSize - 1;
                PartialSum += *pbyte;
                PartialSum = ( PartialSum >> 16 ) + ( PartialSum & 0xFFFF );
            }

            // Compute the final checksum value as the sum of the paritial checksum
            // and the file length.

            return ( DWORD )PartialSum + ImgSize;
        }

        DWORD CPEMgr::calcSizeOfImage( uint8_t* ImageBase )
        {
            uint32_t SizeOfImage = 0;

            auto IMAGE_NT_HDR = GetNTHeaders( (PBYTE)ImageBase ).first;
            auto IMAGE_SECTION_HEADER_ = IMAGE_FIRST_SECTION( IMAGE_NT_HDR );

            // 각 섹션의 크기를 구한다
            for( WORD i = 0; i < IMAGE_NT_HDR->FileHeader.NumberOfSections; ++i )
            {
                SizeOfImage += ROUND_UP( (uint32_t) IMAGE_SECTION_HEADER_[ i ].Misc.VirtualSize, IMAGE_NT_HDR->OptionalHeader.SectionAlignment );
            }

            SizeOfImage += ROUND_UP( (uint32_t) IMAGE_NT_HDR->OptionalHeader.SizeOfHeaders, IMAGE_NT_HDR->OptionalHeader.SectionAlignment );

            return SizeOfImage;
        }

        DWORD CPEMgr::calcSizeOfHeaders( uint8_t* ImageBase )
        {
            uint32_t SizeOfHeaders = 0;

            auto IMAGE_DOS_HDR = ( ( IMAGE_DOS_HEADER* )ImageBase );
            auto IMAGE_NT_HDR = GetNTHeaders( ( PBYTE )ImageBase ).first;

            SizeOfHeaders += IMAGE_DOS_HDR->e_lfanew;
            SizeOfHeaders += sizeof( DWORD );               // NT_HEADERS Signature
            SizeOfHeaders += sizeof( IMAGE_FILE_HEADER );
            if( IMAGE_NT_HDR->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC )
            {
                SizeOfHeaders += sizeof( IMAGE_OPTIONAL_HEADER32 );
                SizeOfHeaders += IMAGE_NT_HDR->FileHeader.NumberOfSections * sizeof( IMAGE_SECTION_HEADER );
                SizeOfHeaders = ROUND_UP( SizeOfHeaders, IMAGE_NT_HDR->OptionalHeader.FileAlignment );
            }
            else if( IMAGE_NT_HDR->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC )
            {
                SizeOfHeaders += sizeof( IMAGE_OPTIONAL_HEADER64 );
                SizeOfHeaders += IMAGE_NT_HDR->FileHeader.NumberOfSections * sizeof( IMAGE_SECTION_HEADER );
                SizeOfHeaders = ROUND_UP( SizeOfHeaders, IMAGE_NT_HDR->OptionalHeader.FileAlignment );
            }
            else
            {

            }

            return SizeOfHeaders;
        }

        DWORD CPEMgr::calcSizeOfRsrc( nsDetail::TyRsrcDirectory* Dir )
        {
            DWORD dwSize = sizeof( IMAGE_RESOURCE_DIRECTORY );

            for( size_t idx = 0; idx < Dir->Entries.size(); ++idx )
            {
                dwSize += sizeof( IMAGE_RESOURCE_DIRECTORY_ENTRY );

                if( Dir->Entries[ idx ]->IsName == true )
                    dwSize += sizeof( IMAGE_RESOURCE_DIR_STRING_U ) + ( Dir->Entries[ idx ]->Name.length() * sizeof( WCHAR ) );

                if( Dir->Entries[ idx ]->IsDirectory == true )
                    dwSize += calcSizeOfRsrc( Dir->Entries[ idx ]->Directory );
                else
                {
                    auto rawSize = Dir->Entries[ idx ]->Leaf->Buffer.size();
                    dwSize += ROUND_UP( rawSize, 8 );
                    dwSize += sizeof( IMAGE_RESOURCE_DATA_ENTRY );
                }
            }

            return dwSize;
        }

        void CPEMgr::writeRsrcSecTo( BYTE* Dst )
        {
            BYTE* Seeker = Dst;

            /*!
             * @brief 리소스 기록 순서
             *  1. Directory
                2. DirectoryEntry
                3. DataEntry
                4. String
                5. raw resource data
                from MakeNSIS
             */

            std::queue<TyRsrcDirectory*> qDirs;             // Used to scan the tree by level
            std::queue<TyRsrcData*> qDataEntries;           // Used for writing the data entries
            std::queue<TyRsrcData*> qDataEntries2;          // Used for writing raw resources data
            std::queue<TyRsrcDirectoryEntry*> qStrings;     // Used for writing resources' names

            qDirs.push( _resRoot );

            while( !qDirs.empty() )
            {
                auto crd = qDirs.front();

                IMAGE_RESOURCE_DIRECTORY rdDir = crd->GetInfo();

                CopyMemory( Seeker, &rdDir, sizeof( IMAGE_RESOURCE_DIRECTORY ) );
                crd->WrittenAt = ( ULONG_PTR )( Seeker );
                Seeker += sizeof( IMAGE_RESOURCE_DIRECTORY );

                for( auto item : crd->Entries )
                {
                    if( item->IsName == true)
                        qStrings.push( item );

                    if( item->IsDirectory == true )
                        qDirs.push( item->Directory );
                    else
                    {
                        qDataEntries.push( item->Leaf );
                        qDataEntries2.push( item->Leaf );
                    }

                    IMAGE_RESOURCE_DIRECTORY_ENTRY rDirE;
                    ZeroMemory( &rDirE, sizeof( rDirE ) );
                    rDirE.DataIsDirectory = item->IsDirectory ? 1 : 0;
                    rDirE.Id = item->IsName ? 0 : item->Id;
                    rDirE.NameIsString = item->IsName ? 1 : 0;

                    CopyMemory( Seeker, &rDirE, sizeof( IMAGE_RESOURCE_DIRECTORY_ENTRY ) );
                    item->WrittenAt = ( ULONG_PTR )( Seeker );
                    Seeker += sizeof( IMAGE_RESOURCE_DIRECTORY_ENTRY );
                }

                qDirs.pop();
            }

            /*
             * Write IMAGE_RESOURCE_DATA_ENTRYs.
             */
            while( !qDataEntries.empty() )
            {
                auto cRDataE = qDataEntries.front();

                IMAGE_RESOURCE_DATA_ENTRY rDataE = { 0, };
                rDataE.CodePage = cRDataE->CodePage;
                rDataE.Size = cRDataE->Buffer.size();

                CopyMemory( Seeker, &rDataE, sizeof( IMAGE_RESOURCE_DATA_ENTRY ) );
                cRDataE->WrittenAt = ( ULONG_PTR )( Seeker );
                Seeker += sizeof( IMAGE_RESOURCE_DATA_ENTRY );

                qDataEntries.pop();
            }

            /*
             * Write strings
             */
            while( !qStrings.empty() )
            {
                auto cRDirE = qStrings.front();

                PIMAGE_RESOURCE_DIRECTORY_ENTRY( cRDirE->WrittenAt )->NameOffset = ( DWORD )( Seeker - Dst );

                WORD iLen = cRDirE->Name.length() + 1;

                *( WORD* )Seeker = iLen;
                CopyMemory( Seeker + sizeof( WORD ), cRDirE->Name.c_str(), iLen * sizeof( WCHAR ) );

                Seeker += ROUND_UP( iLen * sizeof( WCHAR ) + sizeof( WORD ), 4 );

                qStrings.pop();
            }

            /*
             * Write raw resource data and set offsets in IMAGE_RESOURCE_DATA_ENTRYs.
             *
             * 실제 데이터는 8 바이트 경계로 정렬되어 기록되어야한다
             */
            auto NtHDR = GET_NT_HDR_PTR( _base );
            auto rsrcDataDir = GetMemberFromOptionalHeader(NtHDR->OptionalHeader, DataDirectory)[IMAGE_DIRECTORY_ENTRY_RESOURCE];

            while( !qDataEntries2.empty() )
            {
                auto cRDataE = qDataEntries2.front();
                CopyMemory( Seeker, cRDataE->Buffer.data(), cRDataE->Buffer.size() );
                // IMAGE_RESOURCE_DATA_ENTRY 에 기록되는 OffsetToData 는 리소스섹션에서의 Offset 을 기록하지 않고, ImageBase 로부터의 RVA 를 기록한다
                PIMAGE_RESOURCE_DATA_ENTRY( cRDataE->WrittenAt )->OffsetToData = ( DWORD )( Seeker - Dst ) + rsrcDataDir.VirtualAddress;

                Seeker += ROUND_UP( cRDataE->Buffer.size(), 8 );

                qDataEntries2.pop();
            }

            /*
             * Set all of the directory entries offsets.
             */
            setRsrcOffsets( _resRoot, ( ULONG_PTR )( Dst ) );
        }

        DWORD CPEMgr::patchRVAs( PBYTE Src, uint32_t SrcSize, std::vector<uint8_t>& Dst, IMAGE_NT_HEADERS* SrcNtHDR, IMAGE_NT_HEADERS* DstNtHR, DWORD Delta, DWORD RVADelta )
        {
            DWORD Err = ERROR_SUCCESS;
            auto Magic = GetNTHeaders( Src ).first->OptionalHeader.Magic;
            auto SrcDataDirectory = GetMemberFromOptionalHeader( SrcNtHDR->OptionalHeader, DataDirectory );
            auto DstDataDirectory = GetMemberFromOptionalHeader( DstNtHR->OptionalHeader, DataDirectory );
            auto SizeOfHeaders = GetMemberFromOptionalHeader( DstNtHR->OptionalHeader, SizeOfHeaders );

            do
            {
                // Patch Export Section

                auto SrcExportRVA = SrcDataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
                auto SrcExportSec = findSecHDRByRVA( Src, SrcExportRVA );
                auto SrcExportOffset = CvtRVAToOFFSET( SrcExportSec, SrcExportRVA );

                auto DstExportRVA = DstDataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
                auto DstExportSec = findSecHDRByRVA( Dst.data(), DstExportRVA );
                auto DstExportOffset = CvtRVAToOFFSET( DstExportSec, DstExportRVA );

                if( SrcExportOffset != DstExportOffset )
                {
                    IMAGE_EXPORT_DIRECTORY Exp = *AddToPtr<IMAGE_EXPORT_DIRECTORY *>( Src, SrcExportOffset );

                    Exp.Name += RVADelta;
                    Exp.AddressOfFunctions += RVADelta;
                    Exp.AddressOfNames += RVADelta;
                    Exp.AddressOfNameOrdinals += RVADelta;

                    memcpy( AddToPtr( Dst.data(), DstExportOffset ), &Exp, sizeof(Exp) );
                }

                // Patch Relocation Section

                auto SrcRelocSize = SrcDataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size;
                auto SrcRelocRVA = SrcDataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress;
                auto SrcRelocSec = findSecHDRByRVA( Src, SrcRelocRVA );
                auto SrcRelocOffset = CvtRVAToOFFSET( SrcRelocSec, SrcRelocRVA );

                auto DstRelocRVA = DstDataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress;
                auto DstRelocSec = findSecHDRByRVA( Dst.data(), DstRelocRVA );
                auto DstRelocOffset = CvtRVAToOFFSET( DstRelocSec, DstRelocRVA );

                // 리소스 섹션의 시작지점은 Src, Dst 모두 같으므로 아무것이나 사용한다
                auto RsrcRVA = DstDataDirectory[ IMAGE_DIRECTORY_ENTRY_RESOURCE ].VirtualAddress;
                auto RsrcSec = findSecHDRByRVA( Dst.data(), RsrcRVA );
                auto RsrcOffset = CvtRVAToOFFSET( RsrcSec, RsrcRVA );

                int RelocSecDelta = DstRelocOffset - SrcRelocOffset;

                // NOTE: 재배치 기준 섹션이 이동되지 않았더라도, 재배치 기준의 대상이 되는 섹션이 이동되었을 수 있으므로,
                // 재배치 기준 섹션의 오프셋은 비교하지 않음

                ULONG CurrentPos = 0;
                auto SrcRelocPtr = (PBYTE)AddToPtr( Src, SrcRelocOffset );

                while( CurrentPos < SrcRelocSize )
                {
                    auto SrcPbr = (IMAGE_BASE_RELOCATION*)SrcRelocPtr;

                    SrcRelocPtr += sizeof( IMAGE_BASE_RELOCATION );
                    CurrentPos += sizeof( IMAGE_BASE_RELOCATION );

                    if( SrcPbr->SizeOfBlock == 0 )
                        continue;

                    auto tgtPSH = findSecHDRByRVA( Src, SrcPbr->VirtualAddress );
                    if( tgtPSH == 0 )
                        continue;

                    auto RelocCnt = ( int ) (( SrcPbr->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION )) / sizeof( WORD ));

                    // 만약 해당 섹션이 이동되지 않은 섹션이라면 패치할 필요가 없으므로 건너뛴다
                    auto tstOffset = CvtRVAToOFFSET( tgtPSH, SrcPbr->VirtualAddress );

                    if( tstOffset < RsrcOffset )
                    {
                        SrcRelocPtr += sizeof(WORD) * sizeof( RelocCnt );
                        continue;
                    }

                    auto TypeOffsets = (WORD*)SrcPbr;

                    for( auto idx = 0; idx < RelocCnt; ++idx )
                    {
                        WORD Type = ( TypeOffsets[idx] & 0xF0000 ) >> 12;
                        WORD Offset = TypeOffsets[idx] & 0x0FFF;

                        if( Type != IMAGE_REL_BASED_HIGHLOW &&
                            Type != IMAGE_REL_BASED_DIR64 )
                            continue;

                        DWORD SrcItemRVA = SrcPbr->VirtualAddress + Offset;
                        DWORD SrcItemOffset = CvtRVAToOFFSET( tgtPSH, SrcItemRVA );

                        if( SrcItemOffset > RsrcOffset )
                        {
                            if( Type == IMAGE_REL_BASED_HIGHLOW )
                            {
                                *AddToPtr<DWORD*>( Dst.data(),SrcItemOffset + RelocSecDelta ) = *AddToPtr<DWORD*>( Dst.data(),SrcItemOffset + RelocSecDelta ) + RVADelta;
                            }

                            if( Type == IMAGE_REL_BASED_DIR64 )
                            {
                                *AddToPtr<DWORD64*>( Dst.data(),SrcItemOffset + RelocSecDelta ) = *AddToPtr<DWORD64*>( Dst.data(),SrcItemOffset + RelocSecDelta ) + RVADelta;
                            }
                        }
                    }

                    SrcRelocPtr += sizeof(WORD) * sizeof( RelocCnt );
                }

                // Patch Import Section / IAT Table

                auto SrcOffsetRVA = SrcDataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress;
                auto SrcImportSec = findSecHDRByRVA( Src, SrcOffsetRVA );
                auto SrcOffset    = CvtRVAToOFFSET( SrcImportSec, SrcOffsetRVA );

                auto SrcIATRVA = SrcDataDirectory[ IMAGE_DIRECTORY_ENTRY_IAT ].VirtualAddress;
                auto SrcIATSec = findSecHDRByRVA( Src, SrcIATRVA );
                auto SrcIAT    = CvtRVAToOFFSET( SrcIATSec, SrcIATRVA );

                auto DstOffsetRVA = DstDataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress;
                auto DstImportSec = findSecHDRByRVA( Dst.data(), DstOffsetRVA );
                auto DstOffset    = CvtRVAToOFFSET( DstImportSec, DstOffsetRVA );

                auto DstIATRVA = DstDataDirectory[ IMAGE_DIRECTORY_ENTRY_IAT ].VirtualAddress;
                auto DstIATSec = findSecHDRByRVA( Dst.data(), DstIATRVA );
                auto DstIAT    = CvtRVAToOFFSET( DstIATSec, DstIATRVA );

                if( SrcOffset == DstOffset &&
                    SrcIAT == DstIAT )
                    break;

                ULONG i, cmod, cimp;
                IMAGE_IMPORT_DESCRIPTOR *SrcImp, *DstImp;

                auto pfnPatchIATEntries = [&]( DWORD SrcThunk, DWORD DstThunk, ULONG RVADelta ) {

                    auto SrcIATSec = findSecHDRByRVA( Src, SrcThunk );
                    auto SrcIATOff = CvtRVAToOFFSET( SrcIATSec, SrcThunk );

                    auto DstIATSec = findSecHDRByRVA( Dst.data(), DstThunk );
                    auto DstIATOff = CvtRVAToOFFSET( DstIATSec, DstThunk );

                    int idx = 0;
                    if( Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC )
                    {
                        for( ;; )
                        {
                            IMAGE_THUNK_DATA32 IAT = *( IMAGE_THUNK_DATA32* )&Src[ SrcIATOff + idx * sizeof( IMAGE_THUNK_DATA32 ) ];
                            IMAGE_THUNK_DATA32* III = ( IMAGE_THUNK_DATA32* )&Dst[ DstIATOff + idx * sizeof( IMAGE_THUNK_DATA32 ) ];

                            if( IAT.u1.Ordinal == 0 )
                                break;

                            if( ( IAT.u1.Ordinal & IMAGE_ORDINAL_FLAG32 ) == 0 )
                            {
                                IAT.u1.AddressOfData += RVADelta;
                                *III = IAT;
                                cimp++;
                            }

                            idx++;
                        }
                    }
                    else if( Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC )
                    {
                        for( ;; )
                        {
                            IMAGE_THUNK_DATA64 IAT = *( IMAGE_THUNK_DATA64* )&Src[ SrcIATOff + idx * sizeof( IMAGE_THUNK_DATA64 ) ];
                            IMAGE_THUNK_DATA64* III = ( IMAGE_THUNK_DATA64* )&Dst[ DstIATOff + idx * sizeof( IMAGE_THUNK_DATA64 ) ];

                            if( IAT.u1.Ordinal == 0 )
                                break;

                            if( ( IAT.u1.Ordinal & IMAGE_ORDINAL_FLAG64 ) == 0 )
                            {
                                IAT.u1.AddressOfData += RVADelta;
                                *III = IAT;
                                cimp++;
                            }

                            idx++;
                        }
                    }
                };

                for( auto cimp = cmod = 0; ; cmod++ )
                {
                    auto SrcImp = (IMAGE_IMPORT_DESCRIPTOR*)&Src[ SrcOffset + cmod * sizeof( IMAGE_IMPORT_DESCRIPTOR ) ];
                    auto DstImp = (IMAGE_IMPORT_DESCRIPTOR*)&Dst[ DstOffset + cmod * sizeof( IMAGE_IMPORT_DESCRIPTOR ) ];

                    if( SrcImp->FirstThunk == 0 )
                        break;

                    *DstImp = *SrcImp;
                    DstImp->OriginalFirstThunk += RVADelta;
                    DstImp->Name += RVADelta;
                    DstImp->FirstThunk += RVADelta;

                    *(( IMAGE_IMPORT_DESCRIPTOR* )&Dst[ DstOffset + cmod * sizeof( IMAGE_IMPORT_DESCRIPTOR ) ]) = *DstImp;

                    pfnPatchIATEntries( SrcImp->OriginalFirstThunk, DstImp->OriginalFirstThunk, RVADelta );
                    pfnPatchIATEntries( SrcImp->FirstThunk, DstImp->FirstThunk, RVADelta );
                }

            } while( false );

            return Err;
        }

        void CPEMgr::writeRsrcSecPaddingTo( BYTE* res_base, DWORD Size )
        {
            static const BYTE pad[] = { '\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0' };
            DWORD i;

            for( i = 0; i < Size / sizeof pad; i++ )
                memcpy( &res_base[ i * sizeof pad ], pad, sizeof pad );
            memcpy( &res_base[ i * sizeof pad ], pad, Size % sizeof pad );
        }

        void CPEMgr::setRsrcOffsets( nsDetail::TyRsrcDirectory* RsrcDir, ULONG_PTR From )
        {
            for( auto item : RsrcDir->Entries )
            {
                PIMAGE_RESOURCE_DIRECTORY_ENTRY rde = PIMAGE_RESOURCE_DIRECTORY_ENTRY( item->WrittenAt );
                if( item->IsDirectory )
                {
                    rde->DataIsDirectory = 1;
                    rde->OffsetToDirectory = item->Directory->WrittenAt - From;

                    setRsrcOffsets( item->Directory, From );
                }
                else
                {
                    rde->OffsetToData = ( DWORD )( item->Leaf->WrittenAt - From );
                }
            }
        }

        IMAGE_SECTION_HEADER* CPEMgr::retrieveRsrcSection( const PBYTE ImgBase ) const
        {
            auto NtHDR = GET_NT_HDR_PTR( ImgBase );
            auto rsrcDataDir = GetMemberFromOptionalHeader( NtHDR->OptionalHeader, DataDirectory )[IMAGE_DIRECTORY_ENTRY_RESOURCE];

            return findSecHDRByRVA( ImgBase, rsrcDataDir.VirtualAddress );
        }

        DWORD CPEMgr::calcInitializedDataSize( uint8_t* base )
        {
            DWORD sz = 0, num_sections = 0;
            IMAGE_SECTION_HEADER* s;

            s = firstSecHDR( base, &num_sections );

            for( DWORD i = 0; i < num_sections; i++ )
            {
                if( s[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA )
                    sz += s[i].SizeOfRawData;
            }

            return sz;
        }

        std::vector<uint8_t> CPEMgr::getResource( WCHAR* Type, WCHAR* Name, LANGID Language )
        {
            std::vector<uint8_t> Ret;

            nsDetail::TyRsrcDirectory* nameDir = 0;
            nsDetail::TyRsrcDirectory* langDir = 0;
            nsDetail::TyRsrcData* data = 0;

            uint32_t i = _resRoot->FindIndex( Type );
            if( i != UINT_MAX )
            {
                nameDir = _resRoot->GetEntry( i )->Directory;
                i = nameDir->FindIndex( Name );
                if( i != UINT_MAX )
                {
                    langDir = nameDir->GetEntry( i )->Directory;
                    i = 0;
                    if( Language )
                        i = langDir->FindIndex( Language );
                    if( i != UINT_MAX )
                    {
                        data = langDir->GetEntry( i )->Leaf;
                    }
                }
            }

            if( data )
                Ret = data->Buffer;

            return Ret;
        }

        bool CPEMgr::updResource( WCHAR* Type, WCHAR* Name, LANGID Language, uint8_t* Buffer, uint32_t BufferSize )
        {
            nsDetail::TyRsrcDirectory* nameDir = 0;
            nsDetail::TyRsrcDirectory* langDir = 0;
            nsDetail::TyRsrcData* data = 0;

            IMAGE_RESOURCE_DIRECTORY rd = { 0, /*time(0),*/ };
            int iTypeIdx = -1, iNameIdx = -1, iLangIdx = -1;

            iTypeIdx = _resRoot->FindIndex( Type );
            if( iTypeIdx != UINT_MAX )
            {
                nameDir = _resRoot->GetEntry( iTypeIdx )->Directory;
                iNameIdx = nameDir->FindIndex( Name );
                if( iNameIdx != UINT_MAX )
                {
                    langDir = nameDir->GetEntry( iNameIdx )->Directory;
                    iLangIdx = langDir->FindIndex( Language );
                    if( iLangIdx != UINT_MAX )
                    {
                        data = langDir->GetEntry( iLangIdx )->Leaf;
                    }
                }
            }

            if( Buffer != nullptr && BufferSize > 0 )
            {
                // Replace/Add the resource
                if( data )
                {
                    data->SetData( Buffer, BufferSize );
                    return true;
                }

                if( !nameDir )
                {
                    // Type doesn't yet exist
                    nameDir = new nsDetail::TyRsrcDirectory( &rd );
                    _resRoot->AddEntry( new nsDetail::TyRsrcDirectoryEntry( Type, nameDir ) );
                }
                if( !langDir )
                {
                    // Name doesn't yet exist
                    langDir = new nsDetail::TyRsrcDirectory( &rd );
                    nameDir->AddEntry( new nsDetail::TyRsrcDirectoryEntry( Name, langDir ) );
                }
                if( !data )
                {
                    // Language doesn't yet exist, hence data nither
                    data = new nsDetail::TyRsrcData( Buffer, BufferSize );
                    langDir->AddEntry( new nsDetail::TyRsrcDirectoryEntry( MAKEINTRESOURCEW( Language ), data ) );
                }
            }
            else if( data )
            {
                // Delete the resource
                delete data;
                langDir->RemoveEntry( iLangIdx );
                // Delete directories holding the resource if empty
                if( !langDir->CountEntries() )
                {
                    delete langDir;
                    nameDir->RemoveEntry( iNameIdx );
                    if( !nameDir->CountEntries() )
                    {
                        delete nameDir;
                        _resRoot->RemoveEntry( iTypeIdx );
                    }
                }
            }
            else
                return false;

            return true;
        }

        ///////////////////////////////////////////////////////////////////
        /// 디지털 서명 관리

        bool CPEMgr::retrieveSecurityDirOffset( PBYTE ImgBase, DWORD* pdwOfs, DWORD* pdwSize )
        {
            if( ImgBase == nullptr )
                return false;

            IMAGE_DATA_DIRECTORY* idd = retrieveDataDirById(ImgBase, IMAGE_DIRECTORY_ENTRY_SECURITY );

            if( idd == nullptr )
                return false;

            *pdwOfs = idd->VirtualAddress;
            *pdwSize = idd->Size;

            return true;
        }

        bool CPEMgr::retrieveCertificateOffset( PBYTE ImgBase, uint32_t ImgSize, DWORD Idx, DWORD* pdwOfs, DWORD* pdwSize )
        {
            bool isSuccess = false;
            DWORD CertificateDirOffset = 0;
            DWORD CertificateDirSize = 0;

            DWORD Offset = 0;
            DWORD I = 0;

            do
            {
                if( retrieveSecurityDirOffset( ImgBase, &CertificateDirOffset, &CertificateDirSize ) == false )
                    break;

                // 인증서 디렉토리의 파일의 가장 마지막에 붙으며, DirOffset 은 파일에서의 실제 위치와 같다

                while( true )
                {
                    DWORD Pos = CertificateDirOffset + Offset;
                    if( Pos >= ImgSize )
                    {
                        isSuccess = false;
                        break;
                    }


                    DWORD CertificateSize = *AddToPtr<DWORD*>( ImgBase, Pos );
                    if( CertificateSize < sizeof( DWORD ) ||
                        CertificateSize > CertificateDirSize - Offset )
                    {
                        isSuccess = false;
                        break;
                    }

                    if( I == Idx )
                    {
                        *pdwOfs = CertificateDirOffset + Offset;
                        *pdwSize = CertificateSize;
                        isSuccess = true;
                        break;
                    }

                    I++;
                    Offset += CertificateSize;
                    // 해당 영역은 8 바이트 경계로 정렬되어있다
                    if( CertificateSize % 8 )
                        Offset += 8 - ( CertificateSize % 8 );

                    if( Offset >= CertificateSize )
                    {
                        isSuccess = false;
                        break;
                    }
                }

            } while( false );

            return isSuccess;
        }

        bool CPEMgr::removeCertificate( PBYTE& ImgBase, int64_t& ImgSize, _In_ DWORD Index )
        {
            bool isSuccess = false;
            LPWIN_CERTIFICATE CurrentCert;
            DWORD OldCertLength = 0;

            if( ImgBase == nullptr || ImgSize == 0 )
                return false;

            IMAGE_NT_HEADERS* NtHDR = nullptr;

            do
            {
                if( getCertificate( ImgBase, ImgSize, Index, &CurrentCert ) == false)
                    break;

                OldCertLength = CurrentCert->dwLength;
                OldCertLength = (OldCertLength + 7) & ~7;           // The disk size is actually a multiple of 8

                // SizeOfImage 는 실제 파일크기를 반영하지 않을 수 있다.
                // 디지털 서명은 파일의 가장 마지막에 위치하며, VirtualAddress 는 실제 파일 오프셋을 가리킨다.
                // 따라서, 전달받은( 실제 파일 크기 ) 크기를 사용해야한다
                auto Remain = ((DWORD_PTR)CurrentCert) - (DWORD_PTR)ImgBase;
                auto Movement = ImgSize - Remain - OldCertLength;

                auto Dst = (PBYTE)malloc( Remain + Movement );
                memcpy( Dst, ImgBase, Remain );
                if( Movement != 0 )
                    memcpy( Dst + Remain, ImgBase + Remain + OldCertLength, Movement );

                free( ImgBase );
                ImgBase = Dst;
                ImgSize = Remain + Movement;

                auto NtHDR = GetNTHeaders( ImgBase ).first;

                if( NtHDR->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC )
                {
                    ((( PIMAGE_NT_HEADERS32 ) ( NtHDR ))->OptionalHeader ).DataDirectory[ IMAGE_DIRECTORY_ENTRY_SECURITY ].Size -= OldCertLength;
                    if( !(( PIMAGE_NT_HEADERS32 ) ( NtHDR ))->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_SECURITY ].Size )
                    {
                        // Last one removed.  Clear the pointer
                        (( PIMAGE_NT_HEADERS32 ) ( NtHDR ))->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_SECURITY ].VirtualAddress = 0;
                    }
                }
                else
                {
                    (( PIMAGE_NT_HEADERS64 ) ( NtHDR ))->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_SECURITY ].Size -= OldCertLength;
                    if( !(( PIMAGE_NT_HEADERS64 ) ( NtHDR ))->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_SECURITY ].Size )
                    {
                        // Last one removed.  Clear the pointer
                        (( PIMAGE_NT_HEADERS64 ) ( NtHDR ))->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_SECURITY ].VirtualAddress = 0;
                    }
                }

                isSuccess = true;

            } while( false );

            return isSuccess;
        }

        bool CPEMgr::getCertificate( PBYTE ImgBase, uint32_t ImgSize, DWORD Index, LPWIN_CERTIFICATE* Certificate )
        {
            bool isSuccess = false;
            PIMAGE_DATA_DIRECTORY pDataDir = nullptr;
            DWORD_PTR CurrentCert;

            do
            {
                if( IsNTSignature( ImgBase ) == false )
                    break;

                pDataDir = retrieveDataDirById( ImgBase, IMAGE_DIRECTORY_ENTRY_SECURITY );
                if( pDataDir == nullptr )
                    break;

                // Alternative ImgSize -> SizeOfImage
                // GetMemberFromOptionalHeader( GetNTHeaders( ImgBase ).first->OptionalHeader, SizeOfImage )

                // Check if the cert pointer is at least reasonable.
                if (!pDataDir->VirtualAddress ||
                    !pDataDir->Size ||
                    (pDataDir->VirtualAddress + pDataDir->Size > ImgSize ) )
                {
                    break;
                }

                // We're not looking at an empty security slot or an invalid (past the image boundary) value.
                // Let's see if we can find it.
                // 디지털 서명은 VirtualAddress 가 예외적으로 파일의 오프셋이다
                DWORD CurrentIdx = 0;
                DWORD_PTR LastCert;

                CurrentCert = AddToPtr<DWORD_PTR>( ImgBase, pDataDir->VirtualAddress );
                LastCert = CurrentCert + pDataDir->Size;

                while (CurrentCert < LastCert ) {
                    if (CurrentIdx == Index) {
                        isSuccess = true;
                        break;
                    }

                    CurrentIdx++;
                    CurrentCert += ((LPWIN_CERTIFICATE)CurrentCert)->dwLength;
                    CurrentCert = (CurrentCert + 7) & ~7;                       // align it.
                }

            } while( false );

            if( isSuccess == true )
                *Certificate = (LPWIN_CERTIFICATE)CurrentCert;

            return isSuccess;
        }

    } // nsPE
} // nsCmn
